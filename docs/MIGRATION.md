# Migrating to Argon2id

How to move an existing ASP.NET Core Identity application from the stock PBKDF2
password hasher to Argon2id, with **no migration job and no forced password
reset**. Old hashes are upgraded transparently as users sign in.

## TL;DR

Replace your hasher registration with the migrating variant:

```csharp
builder.Services
    .AddIdentityCore<IdentityUser>()
    .AddArgon2idPasswordHasherWithMigration<IdentityUser>()   // <- the only change
    .AddEntityFrameworkStores<AppDbContext>();
```

That's it. From now on:

- **New users / password changes** are hashed with Argon2id immediately.
- **Existing users** sign in against their stored PBKDF2 hash; on the first
  successful sign-in, ASP.NET Core Identity rewrites the stored hash as Argon2id.

## How it works

`AddArgon2idPasswordHasherWithMigration<TUser>()` registers a
[`MigratingPasswordHasher<TUser>`](../src/PostQuantum.Identity/MigratingPasswordHasher.cs)
as the `IPasswordHasher<TUser>`. It routes by stored-hash format:

| Stored value starts with… | Verified by | On success returns |
|---------------------------|-------------|--------------------|
| `$argon2id$` | Argon2id | `Success` (or `SuccessRehashNeeded` if work factors were raised) |
| anything else (PBKDF2, null, garbage) | stock `PasswordHasher<TUser>` | `SuccessRehashNeeded` |

`SuccessRehashNeeded` is the signal ASP.NET Core Identity acts on:
`UserManager.CheckPasswordAsync` (and the sign-in flow) calls `HashPassword`
again and persists the fresh Argon2id hash. Garbage and wrong passwords fail
closed (`Failed`) — the migrating hasher shields you from the stock hasher's
exceptions on malformed input.

## Choosing work factors

The defaults (64 MiB, t=3, p=1) exceed the OWASP minimum. Tune them to your
latency budget and validate the choice with the benchmarks:

```csharp
.AddArgon2idPasswordHasherWithMigration<IdentityUser>(o =>
{
    o.MemorySizeKib = 65536;   // 64 MiB
    o.Iterations    = 3;
})
```

```bash
dotnet run -c Release -f net10.0 --project benchmarks/PostQuantum.Identity.Benchmarks
```

See [`benchmarks/README.md`](../benchmarks/PostQuantum.Identity.Benchmarks/README.md).

## Migrating from something other than PBKDF2

`AddArgon2idPasswordHasherWithMigration` wires the **stock PBKDF2** hasher as the
legacy fallback. If your store uses bcrypt/scrypt/etc., construct the migrating
hasher yourself with your own legacy `IPasswordHasher<TUser>`:

```csharp
services.Replace(ServiceDescriptor.Singleton<IPasswordHasher<TUser>>(sp =>
{
    var argon2id = new Argon2idPasswordHasher<TUser>(sp.GetRequiredService<Argon2idPasswordHasher>());
    IPasswordHasher<TUser> legacy = new MyBcryptPasswordHasher<TUser>();
    return new MigratingPasswordHasher<TUser>(argon2id, legacy);
}));
```

## Verifying the migration

- Pick a test user created under the old hasher; confirm its stored hash does
  **not** start with `$argon2id$`.
- Sign in once with the correct password.
- Re-read the stored hash — it now starts with `$argon2id$v=19$…`.

## Rolling back

Because every Argon2id hash is self-describing (PHC), there is nothing special to
undo: switch the registration back to your previous hasher. Any hashes already
upgraded to Argon2id will only verify with an Argon2id-capable hasher, so keep
this package registered (even as a verify-only fallback) until you are certain no
Argon2id hashes remain.

---

*To God be the glory — 1 Corinthians 10:31.*
