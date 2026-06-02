# PostQuantum.Identity

[![NuGet](https://img.shields.io/nuget/vpre/PostQuantum.Identity?label=nuget&color=blue)](https://www.nuget.org/packages/PostQuantum.Identity)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![.NET](https://img.shields.io/badge/.NET-8.0%20%7C%209.0%20%7C%2010.0-512BD4)](https://dotnet.microsoft.com/)

**Post-quantum integration for ASP.NET Core Identity.** Hashes passwords with
**Argon2id** (the Password Hashing Competition winner) and issues **post-quantum
hybrid JWTs** for authenticated users via [**PostQuantum.Jwt**](https://github.com/systemslibrarian/postquantum-jwt)
— ML-DSA-65 signatures (FIPS 204) with optional X-Wing (X25519 + ML-KEM-768)
encryption. It drops into the standard Identity builder chain and is honest about
exactly what it provides.

> ### Read this first
>
> - **The Argon2id password hasher runs on `net8.0`, `net9.0`, and `net10.0`.**
>   It is a complete, secure-by-default `IPasswordHasher<TUser>` you can adopt
>   today on any of those runtimes.
> - **The post-quantum token service requires `.NET 10.**` The BCL post-quantum
>   primitives (`MLDsa`/`MLKem`) and the PostQuantum.Jwt package ship for .NET
>   10, and on Linux need OpenSSL 3.5+. On `net8.0`/`net9.0` you get the Argon2id
>   hasher only.
> - **The hybrid tokens are intentionally non-interoperable.** They use
>   `alg = ML-DSA-65` — not an IANA-registered JOSE identifier — so they will
>   **not** validate in `System.IdentityModel.Tokens.Jwt`, Auth0/Okta SDKs, or
>   generic JWT tooling. Use this only when **you own both the issuer and every
>   verifier.** See [PostQuantum.Jwt's README](https://github.com/systemslibrarian/postquantum-jwt)
>   for the full rationale.

> **Status — `0.2.0-preview.1`. Preview software. Not for production use.**
> The API may change before 1.0. The cryptographic construction has **not** been
> independently audited. Read [`KNOWN-GAPS.md`](KNOWN-GAPS.md) before depending
> on this for anything that matters.

### What's new in 0.2.0-preview.1

- **Migrate an existing store to Argon2id** with
  `AddArgon2idPasswordHasherWithMigration<TUser>()` — verifies legacy PBKDF2
  hashes and transparently rehashes to Argon2id on the next sign-in.
- **`kid`-based key rotation** — issued tokens carry the configured key id; the
  demo validates a two-key ring with a `SignatureKeyResolver`.
- **AOT/trim-clean token issuance** — claims serialize via source-generated
  `JsonTypeInfo<T>`; the net10 assembly asserts `IsAotCompatible`.
- **Supply chain** — a CycloneDX SBOM is embedded in the `.nupkg`; CI/release
  workflows add a PQ-required test lane and build-provenance attestations.
- **Benchmarks** — a BenchmarkDotNet project for Argon2id work-factor tuning.
- **Demo** now uses the real `PqJwtBearer` authentication handler (`[Authorize]`).

---

## Table of contents

- [Why](#why)
- [Install](#install)
- [60-second tour](#60-second-tour)
- [Password hashing (all runtimes)](#password-hashing-all-runtimes)
- [Hybrid tokens (.NET 10)](#hybrid-tokens-net-10)
- [Public API at a glance](#public-api-at-a-glance)
- [How it fits the PostQuantum.* family](#how-it-fits-the-postquantum-family)
- [Security posture](#security-posture)
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

## Install

```bash
dotnet add package PostQuantum.Identity --prerelease
# or pin the exact preview:
dotnet add package PostQuantum.Identity --version 0.2.0-preview.1
```

Targets `net8.0`, `net9.0`, and `net10.0`. The token features light up on
`net10.0`; the Argon2id hasher works everywhere.

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

---

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

Full detail in [`SECURITY.md`](SECURITY.md). Honest list of what is **not** done
yet in [`KNOWN-GAPS.md`](KNOWN-GAPS.md).

---

## Compatibility

| | net8.0 | net9.0 | net10.0 |
|---|:---:|:---:|:---:|
| Argon2id `IPasswordHasher<TUser>` | ✅ | ✅ | ✅ |
| Post-quantum hybrid token service | — | — | ✅ |

On Linux, the .NET 10 post-quantum primitives require **OpenSSL 3.5+**. Where
ML-DSA is unavailable, token operations fail closed (and the tests skip
themselves with a stated reason).

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

## License

[MIT](LICENSE) © Paul Clark.

---

*To God be the glory — 1 Corinthians 10:31.*
