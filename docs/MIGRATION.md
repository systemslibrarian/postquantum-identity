# Migrating an existing ASP.NET Core Identity store to Argon2id

How to move a real production user store from the stock ASP.NET Core Identity
PBKDF2 hasher (or from bcrypt/scrypt) to Argon2id, **without** a migration job,
**without** locking out a single user, and **without** forcing a password reset.

> **TL;DR — change one line.**
>
> ```diff
>  builder.Services
>      .AddIdentityCore<IdentityUser>()
> -    // (stock PBKDF2 hasher is the default)
> +    .AddArgon2idPasswordHasherWithMigration<IdentityUser>()
>      .AddEntityFrameworkStores<AppDbContext>();
> ```
>
> That single registration call swaps the password hasher for one that
> **verifies legacy PBKDF2 hashes** and **rewrites them as Argon2id on the next
> successful sign-in**. New users hash with Argon2id immediately.

## What you can promise stakeholders before shipping

If you're getting sign-off, here is the shape of the change in plain
operational terms — none of these claims rely on hand-waving:

- **Zero forced password resets.** Every active user keeps signing in with the
  password they already have. The hash gets rewritten under the hood.
- **No migration job and no maintenance window.** The conversion happens
  one user at a time, lazily, during their next successful sign-in.
- **Reversible until the moment a user signs in.** Up to that point the row
  is still PBKDF2; you can swap the registration back without losing anyone.
- **Fail-closed.** A row that is corrupted, garbage, or any unknown legacy
  format never matches — the migrating hasher catches the stock hasher's
  exceptions and returns `Failed`.
- **No new persisted state.** The hasher is a verify-and-rehash function; no
  background tables, no queues, no batch jobs. The PHC string in
  `AspNetUsers.PasswordHash` is the entire state.
- **One package, one dependency.** `PostQuantum.Identity` brings
  `Microsoft.Extensions.Identity.Core` and `Konscious.Security.Cryptography.Argon2`.
  No web-host, no EF runtime, no ambient-context magic.

---

## Table of contents

- [Why a transparent migration is safe to ship](#why-a-transparent-migration-is-safe-to-ship)
- [Step 1 — install the package](#step-1--install-the-package)
- [Step 2 — register the migrating hasher](#step-2--register-the-migrating-hasher)
- [Step 3 — pick work factors that fit your latency budget](#step-3--pick-work-factors-that-fit-your-latency-budget)
- [Step 4 — verify the migration in practice](#step-4--verify-the-migration-in-practice)
- [Migrating from bcrypt / scrypt / a custom hasher](#migrating-from-bcrypt--scrypt--a-custom-hasher)
- [Rolling back](#rolling-back)
- [FAQ](#faq)

---

## Why a transparent migration is safe to ship

ASP.NET Core Identity's password verification pipeline already supports a
"rehash on sign-in" handshake: a hasher can return
`PasswordVerificationResult.SuccessRehashNeeded`, and `UserManager` / the
sign-in manager will re-hash the password with the current hasher and persist
the upgraded value. This is the exact lever transparent migration uses.

PostQuantum.Identity's `MigratingPasswordHasher<TUser>`:

| Stored value starts with… | Verified by | On success returns | On bad input |
|---------------------------|-------------|--------------------|--------------|
| `$argon2id$v=19$…` | Argon2id | `Success` (or `SuccessRehashNeeded` when work factors were raised) | `Failed` (fail-closed) |
| anything else (PBKDF2, garbage) | stock `PasswordHasher<TUser>` | `SuccessRehashNeeded` | `Failed` (fail-closed) |

Implications:

- **No flag day.** Old hashes are upgraded as their owners come back; users who
  never sign in keep their PBKDF2 hash and lose nothing. Eventually the long
  tail can be force-reset, but that's policy, not necessity.
- **No race window.** Identity's existing transaction wraps "verify → rehash",
  so even concurrent sign-ins for the same user upgrade exactly once.
- **No silent failure.** The stock PBKDF2 hasher throws on malformed input;
  `MigratingPasswordHasher<TUser>` catches that and returns `Failed`, so a
  corrupted row never matches anything.

---

## Step 1 — install the package

```bash
dotnet add package PostQuantum.Identity --prerelease
```

Targets `net8.0`, `net9.0`, `net10.0`. The migrating hasher works on **every**
target — you don't need .NET 10 to get the Argon2id half of the library.

---

## Step 2 — register the migrating hasher

Replace whatever wires up `IPasswordHasher<TUser>` today. The single-call form
covers the overwhelmingly common case (stock PBKDF2):

```csharp
using PostQuantum.Identity.DependencyInjection;

builder.Services
    .AddIdentityCore<IdentityUser>()
    .AddArgon2idPasswordHasherWithMigration<IdentityUser>()
    .AddEntityFrameworkStores<AppDbContext>();
```

That's the entire migration. From this point:

- **New users / password changes:** hashed with Argon2id immediately.
- **Existing users:** the first successful sign-in rewrites their stored hash
  as Argon2id; subsequent sign-ins are pure Argon2id.

> **Tip — keep the registration in once you're "done".** Even after you believe
> every active user has been upgraded, leave the migrating hasher in place for
> a release or two so any dormant users still verify cleanly when they return.
> Removing it too early turns "I forgot my password" into "the system rejected
> my password" for nobody's gain.

### What if I use `AddIdentity<TUser, TRole>(…)` (full UI flavour)?

Same thing. `AddIdentity<TUser, TRole>` returns an `IdentityBuilder`, so the
extension chains identically:

```csharp
builder.Services
    .AddIdentity<IdentityUser, IdentityRole>()
    .AddArgon2idPasswordHasherWithMigration<IdentityUser>()
    .AddEntityFrameworkStores<AppDbContext>()
    .AddDefaultTokenProviders();
```

### What if I'm in a Blazor / SignalR / minimal-API host?

It doesn't matter — `AddArgon2idPasswordHasherWithMigration` operates on the
DI container, not on any specific host model. The two demos in
[`samples/`](../samples) show both a minimal-API app and a controller-based
MVC app using the same call.

---

## Step 3 — pick work factors that fit your latency budget

The defaults (64 MiB memory, 3 passes, 1 lane) **exceed** the OWASP 2024
minimum and follow the RFC 9106 second recommended profile. They're a safe
starting point.

If your sign-in path is tight on latency or memory headroom under load, tune
through the options pattern — every emitted hash carries its own parameters,
so changing this value never invalidates prior hashes:

```csharp
.AddArgon2idPasswordHasherWithMigration<IdentityUser>(o =>
{
    o.MemorySizeKib = 65536;   // 64 MiB (default)
    o.Iterations    = 3;       // (default)
    o.DegreeOfParallelism = 1; // (default)
})
```

Use the bundled BenchmarkDotNet harness to validate a profile on real
hardware before shipping it:

```bash
dotnet run -c Release -f net10.0 \
  --project benchmarks/PostQuantum.Identity.Benchmarks
```

OWASP's 2024 recommendation chart for guidance:

| Profile | `MemorySizeKib` | `Iterations` | `DegreeOfParallelism` |
|---|---:|---:|---:|
| OWASP minimum, 2024 | `19456` (19 MiB) | `2` | `1` |
| Library default / RFC 9106 second profile shape | `65536` (64 MiB) | `3` | `1` |
| Stronger / latency-tolerant deployments | `131072` (128 MiB) | `4` | `1` |

Lower bounds are enforced (`< 8 MiB / t<1 / p<1` throws at construction), so
you can't accidentally weaken the hasher below what's safe.

---

## Step 4 — verify the migration in practice

A small end-to-end check before you ship:

1. **Pick a known user** created under the old hasher. Confirm
   `SELECT PasswordHash FROM AspNetUsers WHERE Id = …` does **not** start with
   `$argon2id$`.
2. **Sign in once** with the correct password.
3. **Re-query the same row.** The hash now starts with `$argon2id$v=19$…`.
4. **Sign in again.** Same password, but this time verification goes purely
   through the Argon2id path — and is still successful.
5. **Negative test:** a wrong password must still return `401` (i.e. the
   migration didn't accidentally turn invalid credentials into valid ones).

Track migration coverage with a simple ad-hoc query (good for a Grafana panel
during rollout):

```sql
SELECT
  SUM(CASE WHEN PasswordHash LIKE '$argon2id$%' THEN 1 ELSE 0 END) AS argon2id,
  SUM(CASE WHEN PasswordHash NOT LIKE '$argon2id$%' THEN 1 ELSE 0 END) AS legacy
FROM AspNetUsers;
```

Watch `argon2id` climb monotonically over days as active users sign in.

---

## Migrating from bcrypt / scrypt / a custom hasher

`AddArgon2idPasswordHasherWithMigration<TUser>` wires the **stock PBKDF2**
hasher as the legacy fallback because that is what Identity ships with. If
your store uses something else (BCrypt.Net, scrypt, an in-house hasher), wire
the migrating hasher yourself with your own legacy `IPasswordHasher<TUser>`:

```csharp
using Microsoft.Extensions.DependencyInjection.Extensions;
using PostQuantum.Identity;

services.AddSingleton<Argon2idPasswordHasher>(); // core engine
services.Replace(ServiceDescriptor.Singleton<IPasswordHasher<IdentityUser>>(sp =>
{
    var argon2id = new Argon2idPasswordHasher<IdentityUser>(
        sp.GetRequiredService<Argon2idPasswordHasher>());
    IPasswordHasher<IdentityUser> legacy = new MyBcryptPasswordHasher();
    return new MigratingPasswordHasher<IdentityUser>(argon2id, legacy);
}));
```

The legacy hasher you supply only needs to do **one** thing well: verify the
old hash and return `Success` or `Failed`. The migrating wrapper takes care
of mapping `Success` → `SuccessRehashNeeded` so Identity rewrites the hash on
the next sign-in.

A typical BCrypt.Net adapter is about ten lines:

```csharp
internal sealed class BcryptLegacyHasher : IPasswordHasher<IdentityUser>
{
    public string HashPassword(IdentityUser user, string password) =>
        throw new NotSupportedException("Legacy hasher is verify-only.");

    public PasswordVerificationResult VerifyHashedPassword(
        IdentityUser user, string hashedPassword, string providedPassword)
    {
        try
        {
            return BCrypt.Net.BCrypt.Verify(providedPassword, hashedPassword)
                ? PasswordVerificationResult.Success
                : PasswordVerificationResult.Failed;
        }
        catch
        {
            // Fail-closed on any unexpected library exception.
            return PasswordVerificationResult.Failed;
        }
    }
}
```

The `HashPassword` throw is deliberate — once `MigratingPasswordHasher<TUser>`
is in place, only the Argon2id half ever hashes; the legacy hasher is
verify-only.

---

## Rolling back

Every Argon2id hash is **self-describing** (PHC, version + parameters baked
in) so there is nothing about the upgrade to "undo." To roll back:

1. Restore your previous `IPasswordHasher<TUser>` registration.
2. **Keep `PostQuantum.Identity` in your project** (verify-only is fine) until
   you are certain no Argon2id hashes remain in your store. Otherwise users
   whose hash was upgraded during the trial window will be unable to sign in.

A safer rollback strategy is to keep the migrating hasher registered with its
legacy *and* its Argon2id halves swapped — that path verifies Argon2id stored
hashes too — until you can run a controlled re-hash to whatever you're
rolling back to.

---

## FAQ

**Does this require all my users to reset their passwords?**
No. The whole point of the migrating hasher is to upgrade silently as users
sign in. Forced resets are a separate (and stricter) decision.

**Will old PBKDF2 hashes still verify forever?**
They verify until they are upgraded on next sign-in. After that the row
contains Argon2id, and the legacy path is no longer touched for that user.

**Can I rotate Argon2id work factors later?**
Yes. Raise `MemorySizeKib`/`Iterations`/`DegreeOfParallelism` and ship. Existing
Argon2id hashes whose stored parameters are weaker than the new configuration
will verify, but the hasher will return `SuccessRehashNeeded` and the row will
be re-hashed on the next sign-in — same mechanism, no migration job.

**Is there a script to rehash everyone proactively?**
You don't need one for correctness, and most teams shouldn't run one (it
multiplies offline-cracking surface only minimally and burns CPU). The right
"completion" trigger is usually a calendar deadline at which any user still on
a legacy hash is force-reset on next sign-in.

**Does the migrating hasher slow down sign-in for already-migrated users?**
No. The format check (`IsArgon2idHash`) is an `O(1)` prefix compare; for
already-Argon2id rows the legacy hasher is never invoked. The only overhead
on the *transitional* sign-in is the cost of a single Argon2id rehash —
exactly what would have happened on the next password change anyway.

**Does the migration work with Identity's account lockout, two-factor, and
external login flows?**
Yes — those features sit in front of password verification (lockout) or are
orthogonal to it (2FA, OAuth/OIDC external logins), so the hasher swap is
invisible to them. The standard sign-in manager's "rehash on success" hook
runs regardless of the path that produced the verification.

---

*To God be the glory — 1 Corinthians 10:31.*
