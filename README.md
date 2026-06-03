# PostQuantum.Identity

[![NuGet](https://img.shields.io/nuget/vpre/PostQuantum.Identity?label=nuget&color=blue)](https://www.nuget.org/packages/PostQuantum.Identity)
[![CI](https://github.com/systemslibrarian/postquantum-identity/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/systemslibrarian/postquantum-identity/actions/workflows/ci.yml)
[![CodeQL](https://github.com/systemslibrarian/postquantum-identity/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/systemslibrarian/postquantum-identity/actions/workflows/codeql.yml)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![.NET](https://img.shields.io/badge/.NET-8.0%20%7C%209.0%20%7C%2010.0-512BD4)](https://dotnet.microsoft.com/)

**Post-quantum integration for ASP.NET Core Identity.** Hashes passwords with
**Argon2id** (the Password Hashing Competition winner) and issues **post-quantum
hybrid JWTs** for authenticated users via [**PostQuantum.Jwt**](https://github.com/systemslibrarian/postquantum-jwt)
— ML-DSA-65 signatures (FIPS 204) with optional X-Wing (X25519 + ML-KEM-768)
encryption. It drops into the standard Identity builder chain and is honest about
exactly what it provides.

## Production readiness — at a glance

PostQuantum.Identity ships two surfaces with **different maturity profiles**.
We split the recommendation so the right half lands on the right call:

| Surface | Runtimes | Stance | Why |
|---|---|---|---|
| **Argon2id password hashing** — `Argon2idPasswordHasher`, `MigratingPasswordHasher`, the `IPasswordHasher<TUser>` adapter | net8 / net9 / net10 | **Ready for production use.** | Engine is RFC 9106 §5.3 KAT-pinned, interop-verified against the reference `argon2` CLI, with a PHC wire-format pin and roundtrips across OWASP / RFC 9106 / strong / minimum profiles. Fail-closed, constant-time tag compare, vetted dependency (Konscious). One-line drop-in via `AddArgon2idPasswordHasher` or `AddArgon2idPasswordHasherWithMigration`. |
| **Hybrid post-quantum tokens** — `IPostQuantumTokenService<TUser>`, `PostQuantumTokenOptions`, `AddPostQuantumTokens` | net10 only | **Preview, suitable for owned / trusted ecosystems.** | `alg = ML-DSA-65` is **non-IANA on purpose** — tokens are intentionally not validated by generic JWT tooling. Pair with PostQuantum.Jwt's `PqJwtBearer` handler. Adopt only when **you own both the issuer and every verifier**, e.g. service-to-service inside one fleet. Not for public-internet OIDC. |

> **Status — `0.3.0-preview.1`.** Not yet independently audited; the public API
> may shift before 1.0 (path to 1.0 below). The Argon2id half is implemented to
> production discipline; the hybrid-token half waits on its upstream
> ([PostQuantum.Jwt](https://github.com/systemslibrarian/postquantum-jwt))
> reaching 1.0 and on the IETF JOSE PQC drafts settling. Always read
> [`KNOWN-GAPS.md`](KNOWN-GAPS.md) before committing to it for anything
> load-bearing.

### What's new in 0.3.0-preview.1

- **Argon2id Known Answer Tests, hardened.** RFC 9106 §5.3 reference vector
  (incl. keyed + AD), reference-`argon2`-CLI PHC string verifies through our
  hasher, **PHC emitter wire-format pin**, and **compute → format → verify
  roundtrips** across the OWASP 2024 minimum / library default / stronger /
  documented-minimum profiles.
- **Token KATs.** JOSE header pinned (`typ:JWT`, `alg:ML-DSA-65`, `kid`);
  registered-claim shape + timestamp consistency; single vs. multi-role array
  shape; **sign-then-encrypt envelope KAT** (5-seg JWE, `alg:X-Wing`,
  `enc:A256GCM`, `cty:JWT`); end-to-end recovered-claim equality. ~94% line
  coverage on net10 (71 tests on net10; 49 on net8/net9).
- **Production-shaped samples.** Both demos add `/refresh` (with old-jti
  revocation), `/logout`, in-memory revocation middleware, ProblemDetails
  errors; minimal-API demo adds `/.well-known/pq-jwks` key discovery.
- **Migration story rewritten.** [`docs/MIGRATION.md`](docs/MIGRATION.md) now
  walks PBKDF2, bcrypt/scrypt, work-factor tuning, rollback, and an FAQ.
- **README adds** "When to use this library", a Comparison table vs. default
  Identity / Argon2id-alone / hand-rolled PQ JWT, and a Supply chain section
  with verification commands.

No public API changes from 0.2.

Earlier highlights — **0.2:** `MigratingPasswordHasher` (PBKDF2→Argon2id), `kid`
key rotation, AOT-clean claim path, embedded CycloneDX SBOM, CI/release
workflows, benchmarks. See the [`CHANGELOG`](CHANGELOG.md).

---

## Table of contents

- [Production readiness — at a glance](#production-readiness--at-a-glance)
- [Why](#why)
- [When to use this library](#when-to-use-this-library)
- [Roadmap to 1.0](#roadmap-to-10)
- [Install](#install)
- [Getting started in five minutes](#getting-started-in-five-minutes)
- [60-second tour](#60-second-tour)
- [Password hashing (all runtimes)](#password-hashing-all-runtimes)
  - [One-line opinionated presets](#one-line-opinionated-presets)
  - [Startup-time validation](#startup-time-validation)
  - [DoS protection on Argon2id endpoints](#dos-protection-on-argon2id-endpoints)
- [Hybrid tokens (.NET 10)](#hybrid-tokens-net-10)
  - [IETF JOSE PQC alignment — where the `alg` identifier comes from](#ietf-jose-pqc-alignment--where-the-alg-identifier-comes-from)
- [Try the demo](#try-the-demo)
- [Public API at a glance](#public-api-at-a-glance)
- [How it fits the PostQuantum.* family](#how-it-fits-the-postquantum-family)
- [Comparison with alternatives](#comparison-with-alternatives)
- [Security posture](#security-posture)
- [Supply chain — verifiable in three commands](#supply-chain--verifiable-in-three-commands)
- [Compatibility](#compatibility)
- [Building from source](#building-from-source)
- [License](#license)

---

## Why

ASP.NET Core Identity ships with a solid PBKDF2 password hasher and excellent
user-management plumbing. Two things it does **not** give you out of the box:

1. **Memory-hard password hashing.** PBKDF2 is CPU-hard but cheap on GPUs/ASICs.
   **Argon2id** is memory-hard — the modern default recommended by OWASP and
   standardized in RFC 9106.
2. **Quantum-resistant tokens.** A cryptographically relevant quantum computer
   would break the elliptic-curve math behind today's JWT signatures. **Hybrid**
   post-quantum tokens hedge both classical and quantum risk at once: an attacker
   must break *both* the classical and the post-quantum half.

PostQuantum.Identity combines the two into a single, natural extension of the
Identity builder chain — Argon2id where Identity expects an `IPasswordHasher<TUser>`,
and a token service that turns an authenticated user into a PostQuantum.Jwt
hybrid token.

---

## When to use this library

Four honest checks before you adopt this package. Read them in order — the
first match is the right one.

### ✅ Use PostQuantum.Identity *today* when…

- **You ship ASP.NET Core Identity** and want the password hasher upgraded to
  Argon2id with a one-line registration change and *zero* migration job.
  Production-grade right now. See [`docs/MIGRATION.md`](docs/MIGRATION.md).
- **You issue JWTs to your own services**, you own both the issuer and every
  verifier, and you want hybrid (classical + PQ) signatures *now* ahead of the
  standards landing. The preview maturity is acceptable inside a controlled
  fleet because nothing outside your trust boundary needs to understand
  `alg = ML-DSA-65`.
- **You want a small, focused, vetted dependency surface.** Argon2id comes
  from a widely-used library (Konscious, RFC 9106 KAT-pinned here); ML-DSA /
  ML-KEM come from the .NET BCL. No hand-rolled crypto, no mystery meat.

### ⚠️ Use the *standalone* Argon2id package instead when…

- You **don't ship Identity at all** (a console app, a worker, a non-ASP.NET
  service). Reach for [`Argon2id.PasswordHasher`](https://github.com/systemslibrarian/argon2id-passwordhasher)
  directly — same KAT-pinning, plus peppering, a more general migration
  adapter, and benchmarks, without the Identity contracts.
- You need **a server-held pepper / keyed hashing**. This package's Argon2id
  core is intentionally salt-and-parameters-only; the standalone package adds
  a `PepperRing` for HSM-style secret mixing.

### ⏳ Wait — don't adopt the *token* surface yet when…

- **Your tokens cross trust boundaries to third-party JWT tooling.** Generic
  libraries (`System.IdentityModel.Tokens.Jwt`, Auth0/Okta SDKs, public OIDC
  providers) will reject `alg = ML-DSA-65`. Wait for the IETF JOSE PQC drafts
  to settle, or stay on classical algorithms for that boundary and use this
  library only on the internal hop.
- **Your organization requires a third-party security audit before adoption.**
  This library has not yet been independently audited; the path to 1.0 below
  lists what would unblock that.

### ⛔ Don't use this library when…

- **You're not on ASP.NET Core Identity** at all. The package is built around
  the Identity contracts; without them, nothing about it fits.

## Roadmap to 1.0

The library exits preview when **all** of the following land. Track progress
on each via the GitHub milestones; `KNOWN-GAPS.md` is updated in lockstep.

| Gate | Status |
|---|---|
| Public API frozen for a full minor cycle with no breaking changes | open |
| Upstream [`PostQuantum.Jwt`](https://github.com/systemslibrarian/postquantum-jwt) reaches `1.0.0` (stable) | open — currently `1.0.0-preview.1` |
| IETF JOSE PQC drafts (alg/kty identifiers) reach RFC or stable WG consensus | open |
| Third-party security review of the issuance + verification path | open |
| Fuzz / property-based corpus for the PHC parser and token validator | open |
| Benchmarks tracked in CI with a regression budget | open |

Until those gates close, every release keeps the `-preview.N` suffix and the
honesty-statement in [`SECURITY.md`](SECURITY.md) — even where the underlying
code is already production-quality. Premature 1.0 is a worse sin than honest
preview.

---

## Install

```bash
dotnet add package PostQuantum.Identity --prerelease
# or pin the exact preview:
dotnet add package PostQuantum.Identity --version 0.3.0-preview.1
```

Targets `net8.0`, `net9.0`, and `net10.0`. The token features light up on
`net10.0`; the Argon2id hasher works everywhere.

---

## Getting started in five minutes

The fastest path from `dotnet new` to a working login that returns a
post-quantum hybrid token. Argon2id-only is even shorter — just stop after
step 3.

**1. Create a minimal-API app and add the packages.**

```bash
dotnet new web -n MyApi
cd MyApi
dotnet add package PostQuantum.Identity --prerelease
dotnet add package Microsoft.AspNetCore.Identity.EntityFrameworkCore
dotnet add package Microsoft.EntityFrameworkCore.InMemory
# On .NET 10 only, for token validation in the auth pipeline:
dotnet add package PostQuantum.Jwt.AspNetCore --prerelease
```

**2. Wire Identity with the Argon2id hasher.** Replace the contents of
`Program.cs` with:

```csharp
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using PostQuantum.Identity.DependencyInjection;

var builder = WebApplication.CreateBuilder(args);

builder.Services
    .AddDbContext<AppDb>(o => o.UseInMemoryDatabase("MyApi"))
    .AddIdentityCore<IdentityUser>(o => o.Password.RequiredLength = 8)
    // One line replaces the default PBKDF2 hasher with Argon2id (PHC).
    .AddArgon2idPasswordHasher<IdentityUser>()
    .AddEntityFrameworkStores<AppDb>();

var app = builder.Build();

app.MapPost("/register", async (Creds c, UserManager<IdentityUser> users) =>
    (await users.CreateAsync(new() { UserName = c.Username }, c.Password)).Succeeded
        ? Results.Ok() : Results.BadRequest());

app.Run();

record Creds(string Username, string Password);
sealed class AppDb(DbContextOptions<AppDb> o)
    : Microsoft.AspNetCore.Identity.EntityFrameworkCore.IdentityDbContext<IdentityUser>(o);
```

`dotnet run` — you have an Identity app whose passwords are hashed with
Argon2id. Done with the password-only path.

**3. Migrating an existing store?** Swap one line:

```diff
- .AddArgon2idPasswordHasher<IdentityUser>()
+ .AddArgon2idPasswordHasherWithMigration<IdentityUser>()
```

Old PBKDF2 hashes verify under the legacy path and rehash to Argon2id on the
next successful sign-in. No migration job. Full guide:
[`docs/MIGRATION.md`](docs/MIGRATION.md).

**4. Add post-quantum hybrid tokens** (.NET 10 only). Provision an ML-DSA-65
key out of band, then extend the registration:

```csharp
using System.Security.Cryptography;
using PostQuantum.Identity.Tokens;
using PostQuantum.Jwt;
using PostQuantum.Jwt.AspNetCore;

// ... existing AddIdentityCore + AddArgon2idPasswordHasher chain ...
    .AddPostQuantumTokens<IdentityUser>(o =>
    {
        o.SigningKey = signingKey;             // your provisioned ML-DSA-65 key
        o.KeyId      = "k-2026-06";            // stamped into the token's kid
        o.Issuer     = "https://issuer.example";
        o.Audience   = "api://my-fleet";
        o.Lifetime   = TimeSpan.FromHours(1);
    });

builder.Services
    .AddAuthentication(PqJwtBearerDefaults.AuthenticationScheme)
    .AddPqJwtBearer(o => o.ValidationParameters = new PqJwtValidationParameters
    {
        SignatureKeyResolver = kid => kid == "k-2026-06" ? verifyingKey : null,
        ValidIssuer   = "https://issuer.example",
        ValidAudience = "api://my-fleet",
    });
builder.Services.AddAuthorization();
```

Issue tokens in your `/login` endpoint via the injected
`IPostQuantumTokenService<IdentityUser>`; validate them by adding
`[Authorize]` to any endpoint. Two runnable, production-shaped samples
([minimal API](samples/PostQuantum.Identity.Demo) and
[MVC](samples/PostQuantum.Identity.Mvc.Demo)) show the full pattern with
`/refresh`, `/logout`, `kid`-based rotation, and a JWKS-style key endpoint.

---

## 60-second tour

```csharp
using Microsoft.AspNetCore.Identity;
using PostQuantum.Identity.DependencyInjection;

builder.Services
    .AddIdentityCore<IdentityUser>()
    // Argon2id replaces the default PBKDF2 hasher (net8.0 / net9.0 / net10.0):
    .AddArgon2idPasswordHasher<IdentityUser>()
    .AddEntityFrameworkStores<AppDbContext>();
```

```csharp
// .NET 10 only — issue a post-quantum hybrid token for a signed-in user:
using PostQuantum.Identity.Tokens;

builder.Services
    .AddIdentityCore<IdentityUser>()
    .AddArgon2idPasswordHasher<IdentityUser>()
    .AddPostQuantumTokens<IdentityUser>(o =>
    {
        o.SigningKey = mlDsa65PrivateKey;        // your provisioned ML-DSA-65 key
        o.Issuer     = "https://issuer.example";
        o.Audience   = "api://resource";
        o.Lifetime   = TimeSpan.FromHours(1);
    })
    .AddEntityFrameworkStores<AppDbContext>();

// In a login endpoint:
var token = await tokenService.CreateTokenAsync(user);   // signed with ML-DSA-65
```

A runnable version of exactly this lives in
[`samples/PostQuantum.Identity.Demo`](samples/PostQuantum.Identity.Demo).

---

## Password hashing (all runtimes)

The Argon2id hasher is **secure by default** and **self-describing**: every hash
is a PHC string (`$argon2id$v=19$m=65536,t=3,p=1$<salt>$<hash>`) carrying its own
work factors, so changing your configuration never breaks verification of
existing hashes.

```csharp
var hasher = new Argon2idPasswordHasher();          // 64 MiB, t=3, p=1 defaults

string stored = hasher.HashPassword("correct horse battery staple");

VerifyResult result = hasher.Verify("correct horse battery staple", stored);
// result.Success     -> true
// result.NeedsRehash -> true when the stored hash used weaker params than current
```

Wired into Identity, a weaker stored hash transparently reports
`PasswordVerificationResult.SuccessRehashNeeded`, so ASP.NET Core Identity
**upgrades it on the next successful sign-in** — no migration job required.

Tune the work factors through the standard options pattern:

```csharp
.AddArgon2idPasswordHasher<IdentityUser>(o =>
{
    o.MemorySizeKib = 131072;   // 128 MiB
    o.Iterations    = 4;
})
```

Defaults exceed the OWASP minimum and follow the RFC 9106 second recommended
profile. The lower bounds are enforced — a configuration weaker than 8 MiB
throws at construction rather than silently degrading security.

### One-line opinionated presets

Most teams don't want to tune Argon2id parameters by hand. Four named factory
methods on `Argon2idOptions` and a one-line DI overload cover the realistic
environment classes:

```csharp
// Pick one — values are copied at registration time, so the preset is decoupled
// from anything you mutate afterwards.
.AddArgon2idPasswordHasher<IdentityUser>(Argon2idOptions.RecommendedDefault())
.AddArgon2idPasswordHasher<IdentityUser>(Argon2idOptions.OwaspMinimum())
.AddArgon2idPasswordHasher<IdentityUser>(Argon2idOptions.HighSecurity())
.AddArgon2idPasswordHasher<IdentityUser>(Argon2idOptions.LowMemoryContainer())
```

| Preset | Memory | Iterations | Parallelism | Right for |
|---|---:|---:|---:|---|
| `RecommendedDefault()` (≡ the parameterless default) | 64 MiB | 3 | 1 | Server APIs, typical SaaS, default pick |
| `OwaspMinimum()` | 19 MiB | 2 | 1 | Latency-sensitive endpoints, modest hardware |
| `HighSecurity()` | 128 MiB | 4 | 1 | Admin consoles, key-derivation paths, KDF use |
| `LowMemoryContainer()` | 16 MiB | 4 | 1 | Tight K8s pods / burstable VMs (trades memory for iterations) |

All four pass `Argon2idOptions.Validate()` and have a Known-Answer-Test
asserting their published profile. Both the `AddArgon2idPasswordHasher` and
the `AddArgon2idPasswordHasherWithMigration` extension methods have the same
one-line preset overload.

### Startup-time validation and preflight logging

A misconfigured work factor (`MemorySizeKib = 1024` and friends) used to
throw on the first hash — i.e. when a real user tried to sign in. The DI
helpers now register an `IValidateOptions<Argon2idOptions>` so a bad
configuration fails when the host starts, with a message naming the offending
property and value. Production deployments boot-fail visibly instead of
shipping the misconfig and surprising the on-call rotation later.

For the inverse case — *valid* config that you nevertheless want confirmed
in the startup log — opt into a one-shot preflight diagnostic:

```csharp
builder.Services
    .AddArgon2idPasswordHasher<IdentityUser>(Argon2idOptions.RecommendedDefault())
    .Services
    .AddPostQuantumPreflightLogging();   // one INFO line at boot
```

It writes a single structured INFO line summarising the resolved Argon2id
work factors and the approximate per-call memory budget. Never logs key
material, plaintext passwords, or token contents (regression-tested with
sentinel-string assertions).

### DoS protection on Argon2id endpoints

Argon2id is *deliberately expensive* — that's how it raises the offline
cracking cost — but that also means a misbehaving client can burn
disproportionate server CPU by spamming bogus `/login` or `/register` calls.
Pair the hasher with an ASP.NET Core rate limiter on the auth endpoints:

```csharp
builder.Services.AddRateLimiter(o => o.AddPolicy("auth", ctx =>
    RateLimitPartition.GetFixedWindowLimiter(
        partitionKey: ctx.Connection.RemoteIpAddress?.ToString() ?? "anon",
        factory: _ => new FixedWindowRateLimiterOptions
        {
            PermitLimit = 10,
            Window = TimeSpan.FromSeconds(30),
        })));

app.UseRateLimiter();

app.MapPost("/login", /* … */).RequireRateLimiting("auth");
app.MapPost("/register", /* … */).RequireRateLimiting("auth");
```

Both samples ([minimal API](samples/PostQuantum.Identity.Demo), [MVC](samples/PostQuantum.Identity.Mvc.Demo))
wire this exact pattern. Pair the in-process limiter with edge-level limits
(CDN / API gateway / WAF) for real deployments — the in-process limiter is
the last line of defense, not the whole story.

### Migrating an existing store

If your users were created with the stock ASP.NET Core Identity PBKDF2 hasher,
use the migrating registration instead. It verifies legacy hashes with PBKDF2 and
rehashes them to Argon2id on the next successful sign-in — no migration job, no
forced password reset:

```csharp
builder.Services
    .AddIdentityCore<IdentityUser>()
    .AddArgon2idPasswordHasherWithMigration<IdentityUser>()
    .AddEntityFrameworkStores<AppDbContext>();
```

New registrations are hashed with Argon2id immediately; the legacy path is only
taken for pre-existing PBKDF2 hashes and disappears as users sign in.

---

## Hybrid tokens (.NET 10)

`IPostQuantumTokenService<TUser>` reads the subject's identity, roles, and claims
through `UserManager<TUser>` and issues a PostQuantum.Jwt token:

- **Signature — ML-DSA-65** (FIPS 204). Signing is mandatory; there is no
  `alg: none` path.
- **Optional encryption — X-Wing** (X25519 + ML-KEM-768) + AES-256-GCM, by
  setting `EncryptForRecipient`.
- **Claims** — `sub` is the Identity user id; `name`, `email`, roles
  (`role` by default), and the user's persisted claims are added per the options.

```csharp
var token = await tokenService.CreateTokenAsync(user, cancellationToken);
```

Validation is done with PostQuantum.Jwt's `PqJwtValidator` (fail-closed: any
tamper, wrong audience, or expiry throws). See the demo's `/me` endpoint for a
worked example, or use the
[`PostQuantum.Jwt.AspNetCore`](https://github.com/systemslibrarian/postquantum-jwt)
bearer handler to slot it into the standard auth pipeline.

### Crypto agility — key rotation and algorithm rotation

PostQuantum.Identity assumes you'll rotate signing keys (routine) and
eventually rotate signature algorithms (when standards or analysis evolve).
Both are first-class operations.

**Key rotation (`kid`)** — the routine case, demonstrated end-to-end in the
minimal-API demo. Stamp `PostQuantumTokenOptions.KeyId` into each issued
token; the verifier's `SignatureKeyResolver` maps `kid` → public key, so
tokens signed by either the current or previous key validate during the
overlap window:

```csharp
// Issuer: stamp the current kid into every token.
o.SigningKey = signingKeyRing[CurrentKeyId];
o.KeyId      = CurrentKeyId;

// Verifier: resolve the right public key by kid.
o.ValidationParameters = new PqJwtValidationParameters
{
    SignatureKeyResolver = kid => verifyingKeyRing.GetValueOrDefault(kid ?? ""),
    ValidIssuer   = Issuer,
    ValidAudience = Audience,
};
```

Rotation procedure:
1. Add new `kid` (and key) to the verifier's resolver.
2. Wait one verifier-deployment cycle (so every verifier holds the new key).
3. Flip the issuer to sign with the new `kid`.
4. Wait one `Lifetime` (so every active token issued under the old key has
   naturally expired).
5. Retire the old `kid` from the resolver.

**Algorithm rotation** — the eventual case, when (a) NIST publishes a
parameter-set update inside ML-DSA, (b) the IETF JOSE PQC drafts finalize
new identifiers, or (c) a weakness is found and you need to migrate off
ML-DSA-65 entirely. The pattern is the same shape as kid rotation, scaled
up one level:

- During a transition window, **issue under the new algorithm immediately**
  but keep the **verifier accepting both** (the validator's
  `SignatureKeyResolver` already keys on `kid`; allocate distinct kids per
  algorithm so the resolver can route to the right primitive).
- This depends on **upstream PostQuantum.Jwt exposing dual-alg validation**
  in a future release. Until then, in-place algorithm rotation is a hard
  cutover. The `kid`-per-algorithm pattern still gives you a clear
  rollback point — switch the issuer back to the previous `kid` and the
  old verifier path continues to work.

**No PostQuantum.Identity API change is required** when upstream
PostQuantum.Jwt adopts standardized identifiers or new algorithm
parameter sets. You pick them up via a normal version bump.

### IETF JOSE PQC alignment — where the `alg` identifier comes from

A common, fair question: *"why doesn't `alg = ML-DSA-65` validate in
Java/Node/Rust JWT libraries?"* The honest answer is in two parts.

**Where the identifier is stamped.** The wire-level `alg` / `enc` headers
(`ML-DSA-65`, `X-Wing`, `A256GCM`) are written by the upstream
[PostQuantum.Jwt](https://github.com/systemslibrarian/postquantum-jwt)
builder — not by this package. PostQuantum.Identity consumes the builder; it
does not pick the identifier. So changing it cannot happen in this repo
alone; it happens upstream and we inherit.

**Why it's intentionally non-IANA today.** The IETF JOSE working group's
post-quantum JWS algorithm registration is still in flight
([`draft-ietf-jose-pq-jose-extensions`](https://datatracker.ietf.org/doc/draft-ietf-jose-pq-jose-extensions/),
[`draft-ietf-cose-dilithium`](https://datatracker.ietf.org/doc/draft-ietf-cose-dilithium/),
related COSE work). The final wire names — `ML-DSA-65`, `MLDSA65`,
numeric codepoints, something else — have not settled. Shipping a *placeholder*
IANA-ish identifier today and renaming it on RFC publication would create
exactly the cross-ecosystem breakage adopters fear. Until the drafts
finalize, we use a descriptive, deliberately distinct name so anyone
verifying a token knows they need a PQ-aware validator, not a generic one.

**How that becomes painless later.** When the drafts reach RFC or stable WG
consensus, PostQuantum.Jwt will publish a release that adopts the
standardized identifiers; PostQuantum.Identity picks them up via a normal
version bump — **no PostQuantum.Identity API change required**. Java / Node /
Rust libraries implementing the same RFC will then verify tokens issued by
this library across ecosystems.

This is the single largest gate on the [Roadmap to 1.0](#roadmap-to-10) for
the token surface. Track upstream progress at the PostQuantum.Jwt repo and
the IETF JOSE / COSE working group datatracker.

---

## Try the demo

Two runnable samples wire all of this into a real ASP.NET Core app with an
in-memory store — nothing to install:

- [`samples/PostQuantum.Identity.Demo`](samples/PostQuantum.Identity.Demo) —
  minimal APIs, `PqJwtBearer` `[Authorize]`, and `kid`-based key rotation.
- [`samples/PostQuantum.Identity.Mvc.Demo`](samples/PostQuantum.Identity.Mvc.Demo) —
  the same wiring with controller-based MVC.

```bash
# One command. (LD_LIBRARY_PATH is only needed where the system OpenSSL
# predates 3.5 — password hashing works regardless.)
LD_LIBRARY_PATH=/opt/conda/lib ASPNETCORE_URLS=http://localhost:5199 \
  dotnet run --project samples/PostQuantum.Identity.Demo
```

```bash
# In another terminal:
curl -s -X POST localhost:5199/register -H 'Content-Type: application/json' \
  -d '{"username":"ada","password":"Lovelace#1843"}'

TOKEN=$(curl -s -X POST localhost:5199/login -H 'Content-Type: application/json' \
  -d '{"username":"ada","password":"Lovelace#1843"}' | jq -r .token)

curl -s localhost:5199/me -H "Authorization: Bearer $TOKEN"
# -> { "subject": "...", "name": "ada", "roles": [] }
```

Register hashes the password with Argon2id; login returns an ML-DSA-65–signed
post-quantum token; `/me` is validated by the `PqJwtBearer` handler. A wrong
password or a tampered token returns `401` — fail-closed.

## Public API at a glance

| Type | Runtime | Purpose |
|------|---------|---------|
| `Argon2idPasswordHasher` | net8/9/10 | Core hasher: `HashPassword`, `Verify`, `NeedsRehash`, `IsArgon2idHash` |
| `Argon2idPasswordHasher<TUser>` | net8/9/10 | `IPasswordHasher<TUser>` adapter for Identity |
| `MigratingPasswordHasher<TUser>` | net8/9/10 | Argon2id for new hashes; legacy hasher for old ones, rehash-on-login |
| `Argon2idOptions` | net8/9/10 | Work factors (`m`, `t`, `p`, salt/hash sizes) + `Validate()` |
| `VerifyResult` | net8/9/10 | `Success` + `NeedsRehash` from one verification |
| `IPostQuantumTokenService<TUser>` | net10 | Issues hybrid tokens for a user |
| `PostQuantumTokenOptions` | net10 | Signing key, `KeyId`, issuer/audience, lifetime, claim mapping |
| `AddArgon2idPasswordHasher<TUser>(…)` | net8/9/10 | DI: register the hasher |
| `AddArgon2idPasswordHasherWithMigration<TUser>(…)` | net8/9/10 | DI: register the migrating hasher |
| `AddPostQuantumTokens<TUser>(…)` | net10 | DI: register the token service |

---

## How it fits the PostQuantum.* family

PostQuantum.Identity is the ASP.NET Core Identity layer of a broader family:

- [**PostQuantum.Jwt**](https://github.com/systemslibrarian/postquantum-jwt) —
  the hybrid JWT engine this package issues tokens with.
- [**postquantum-aspnetcore**](https://github.com/systemslibrarian/postquantum-aspnetcore) —
  the `AddPqJwtBearer` authentication handler for validating those tokens.
- [**argon2id-passwordhasher**](https://github.com/systemslibrarian/argon2id-passwordhasher) —
  a standalone, more feature-rich Argon2id package (peppering, migration adapter,
  benchmarks). PostQuantum.Identity ships its own focused Argon2id core so it has
  no hard dependency on that package; see [`KNOWN-GAPS.md`](KNOWN-GAPS.md) for the
  relationship.

---

## Comparison with alternatives

| | **Default Identity** (PBKDF2) | **Argon2id alone**<br/>(`Argon2id.PasswordHasher`) | **PostQuantum.Identity** (this) | **Hand-rolled PQ JWT** |
|---|:---:|:---:|:---:|:---:|
| Password hashing | PBKDF2 (CPU-hard only) | Argon2id ✅ | Argon2id ✅ | — |
| OWASP-recommended hash | ❌ | ✅ | ✅ | — |
| `IPasswordHasher<TUser>` adapter | built-in | needs glue | **built-in** | — |
| PBKDF2 → Argon2id transparent migration | n/a | manual adapter | **one-line registration** | — |
| Quantum-resistant token signature | ❌ (RSA/ECDSA) | — | **ML-DSA-65 (FIPS 204)** | depends |
| Hybrid (classical + PQ) confidentiality | ❌ | — | **X-Wing + AES-256-GCM** | depends |
| Fail-closed validation (no `alg: none`) | n/a | — | ✅ | depends on yours |
| Validates in generic JWT libraries | ✅ | n/a | **❌** (non-IANA `alg`) | depends |
| Independent audit | n/a (Microsoft-shipped) | ❌ (preview) | **❌ (preview, stated)** | depends |
| Supply chain — SBOM + provenance | n/a | embedded SBOM | **embedded SBOM + GitHub attestation** | yours to provide |
| RFC 9106 Known Answer Tests pinned in CI | n/a | ✅ | **✅ (RFC 9106 §5.3 + CLI interop + emitter pin)** | varies |

**How to read this table.** Default Identity is fine for many apps today —
its weakness is PBKDF2 and the absence of any post-quantum story, not
buggy code. The standalone Argon2id package is the right pick when you're
*not* on Identity. Hand-rolling a PQ JWT is possible (the BCL primitives
are there) but takes you into wire-format, KAT-pinning, and supply-chain
territory you probably don't want to own. PostQuantum.Identity puts the
hardened pieces of all three on Identity's builder chain with one line of
registration each.

---

## Security posture

- **Fail-closed, always.** Malformed stored hashes never verify; token validation
  raises on any tamper, wrong audience, or expiry. No silent downgrade.
- **Memory zeroing.** UTF-8 password bytes and computed candidates are wiped with
  `CryptographicOperations.ZeroMemory` after use.
- **Constant-time comparison.** Hash comparison uses
  `CryptographicOperations.FixedTimeEquals`.
- **Don't roll your own crypto.** Argon2id comes from
  [Konscious.Security.Cryptography](https://github.com/kmaragon/Konscious.Security.Cryptography);
  ML-DSA / ML-KEM come from the native .NET BCL via PostQuantum.Jwt.
- **Key management is yours.** This library never generates, stores, or rotates
  signing keys for you.
- **Tested against the spec.** Argon2id is checked against the RFC 9106 §5.3
  reference vector and a reference-`argon2`-CLI PHC string; the token surface has
  a fail-closed corpus (expiry, wrong key, per-segment tamper, malformed input).

Full detail in [`SECURITY.md`](SECURITY.md). Honest list of what is **not** done
yet in [`KNOWN-GAPS.md`](KNOWN-GAPS.md).

---

## Supply chain — verifiable in three commands

A library you can't independently verify isn't really yours to trust. The
package you pull from NuGet is **built deterministically in GitHub Actions**,
**ships its own SBOM**, and **carries a GitHub build-provenance attestation
signed by Sigstore**. Anyone can verify the whole chain in three commands:

```bash
# 1. Pull the package from nuget.org.
nuget install PostQuantum.Identity -Version 0.3.0-preview.1 -OutputDirectory ./pkg
PKG=./pkg/PostQuantum.Identity.0.3.0-preview.1/PostQuantum.Identity.0.3.0-preview.1.nupkg

# 2. Inspect the embedded CycloneDX SBOM (covers all three TFMs).
unzip -p "$PKG" bom.json | jq '{ format: .bomFormat, spec: .specVersion,
  components: (.components | length) }'

# 3. Verify the GitHub build-provenance attestation for that exact .nupkg.
gh attestation verify "$PKG" --owner systemslibrarian
```

A passing verify proves the `.nupkg` was built by *this* repo's
[`release.yml`](.github/workflows/release.yml) workflow, from a specific
commit, in GitHub's hosted runners — not assembled or substituted in between.

### What goes into the package

| Hygiene | How it lands in your hands |
|---|---|
| **CycloneDX SBOM** embedded at `bom.json` | Generated from the *multi-target* dependency graph (no TFM collapses), so transitive deps for net8 / net9 / net10 stay distinct. Verify with the `unzip -p` line above. |
| **Build-provenance attestation** | Released by [`release.yml`](.github/workflows/release.yml) via [`actions/attest-build-provenance`](https://github.com/actions/attest-build-provenance) for every `.nupkg` and `.snupkg`. Sigstore-signed; verifiable with `gh attestation verify`. |
| **Deterministic builds** | `Deterministic=true`, `ContinuousIntegrationBuild=true` under CI. Two builds of the same commit produce byte-equal assemblies. |
| **SourceLink** + `.snupkg` symbols | Stack traces from a deployed `.nupkg` jump straight to the matching commit in this repo. |
| **Pinned dependency surface** | `Konscious.Security.Cryptography.Argon2` (Argon2 1.3 spec impl) — every TFM. `Microsoft.Extensions.Identity.Core` — every TFM. `PostQuantum.Jwt` — **net10 only**, gated by `#if NET10_0_OR_GREATER`. No web-host or EF deps pulled in. |
| **Dependabot** | Configured in [`.github/dependabot.yml`](.github/dependabot.yml) — upstream bumps land as PRs. |
| **CodeQL** on every PR and push | [`codeql.yml`](.github/workflows/codeql.yml) — results land in GitHub's Security tab; CI blocks the push on a critical finding. |
| **Version-sync check** in CI | [`scripts/check-version-sync.sh`](scripts/check-version-sync.sh) fails the build if the csproj, README, and CHANGELOG versions diverge. |

### Reproducing a build locally

```bash
git clone https://github.com/systemslibrarian/postquantum-identity
cd postquantum-identity
git checkout v0.3.0-preview.1   # or your tag of interest
dotnet pack src/PostQuantum.Identity/PostQuantum.Identity.csproj -c Release -o ./local
# The assemblies inside ./local/*.nupkg are byte-equal to the published ones
# at the same commit (within toolchain-version equivalence).
```

---

## Compatibility

### Per-target-framework surface availability

| | net8.0 | net9.0 | net10.0 |
|---|:---:|:---:|:---:|
| Argon2id `IPasswordHasher<TUser>` | ✅ | ✅ | ✅ |
| Migrating PBKDF2 → Argon2id hasher | ✅ | ✅ | ✅ |
| Opinionated work-factor presets | ✅ | ✅ | ✅ |
| Startup-time `IValidateOptions` | ✅ | ✅ | ✅ |
| Post-quantum hybrid token service | — | — | ✅ |
| ML-DSA-65 signature & verification | — | — | ✅ |
| X-Wing hybrid encryption | — | — | ✅ |
| Source-generated AOT-clean claim path | — | — | ✅ |

### Per-OS / per-runtime support

| OS | Argon2id | Token service | Notes |
|---|:---:|:---:|---|
| **Windows 11 / Server 2022+ (x64, ARM64)** | ✅ | ✅ | ML-DSA via Windows CNG. CI runs Windows lane on every PR. |
| **Linux — glibc, OpenSSL ≥ 3.5** | ✅ | ✅ | Modern distros (Ubuntu 25.04+, Fedora 40+, RHEL 10 once it ships). CI runs a "PQ-required" lane pinning OpenSSL 3.5+ via conda-forge — any skipped PQ test there fails the build. |
| **Linux — glibc, OpenSSL 3.0.x – 3.4.x** | ✅ | ⚠️ skipped | Argon2id runs; `MLDsa.IsSupported` returns `false`, so token operations 503 with a clear `ProblemDetails`. Pin a 3.5+ provider via `LD_LIBRARY_PATH` (the docker / dev-container pattern) to light up tokens. |
| **macOS 13+ (Intel and Apple Silicon)** | ✅ | ⚠️ untested | Argon2id is pure managed code — no concern. Token surface depends on the .NET 10 BCL's macOS ML-DSA path; we haven't run it in CI yet. Treat as best-effort until that lane lands. |
| **Alpine / musl** | ✅ | ⚠️ untested | Argon2id works; token surface depends on the musl OpenSSL build supplying an ML-DSA-capable provider — set up case-by-case. |

### Container constraints

| Container size | Recommended preset | Approx per-hash cost |
|---|---|---|
| **Tiny K8s pod / burstable VM** (< 256 MiB total) | `Argon2idOptions.LowMemoryContainer()` (16 MiB, t=4) | ~16 MiB allocated + freed per `HashPassword` / `Verify` |
| **Standard API pod** (512 MiB – 2 GiB) | `Argon2idOptions.RecommendedDefault()` (64 MiB, t=3) | ~64 MiB per call |
| **Beefy admin / KDF service** (≥ 4 GiB) | `Argon2idOptions.HighSecurity()` (128 MiB, t=4) | ~128 MiB per call |

Argon2id allocates its memory block **per-call**, freed when the call
returns. Concurrent sign-ins on the same pod multiply this — size pod
memory limits as `(per-hash memory) × (concurrent-sign-in budget) + headroom`.
The bundled rate-limiter pattern caps concurrent budget; tune in tandem.

### CPU architecture

The library is pure-managed and CPU-architecture-agnostic. The Argon2id
inner loop and the BCL PQC primitives benefit from SIMD where the platform
provides it (AVX2 / AVX-512 on x64, Neon on ARM64), but there is no
hand-rolled intrinsics path in this library — performance follows the
runtime + dependency choices, not anything we ship.

---

## Building from source

```bash
dotnet build
dotnet test
```

The token tests touch the native ML-DSA primitive and skip themselves when the
host's OpenSSL is too old. To run the full suite in this dev container (whose
system OpenSSL predates ML-DSA), point the loader at conda's OpenSSL 3.5+:

```bash
LD_LIBRARY_PATH=/opt/conda/lib dotnet test
```

---

## Contributing

Issues and PRs welcome — please read [`CONTRIBUTING.md`](CONTRIBUTING.md) and the
[`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) first. For migrating an existing store
see [`docs/MIGRATION.md`](docs/MIGRATION.md); design decisions are recorded in
[`docs/adr/`](docs/adr/). Security issues: follow [`SECURITY.md`](SECURITY.md)
(private disclosure) — never a public issue.

## License

[MIT](LICENSE) © Paul Clark.

---

*To God be the glory — 1 Corinthians 10:31.*
