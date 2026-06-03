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

> **Status — `0.3.0-preview.1`. Preview software. Not for production use.**
> The API may change before 1.0. The cryptographic construction has **not** been
> independently audited. Read [`KNOWN-GAPS.md`](KNOWN-GAPS.md) before depending
> on this for anything that matters.

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

- [Why](#why)
- [When to use this library](#when-to-use-this-library)
- [Install](#install)
- [60-second tour](#60-second-tour)
- [Password hashing (all runtimes)](#password-hashing-all-runtimes)
- [Hybrid tokens (.NET 10)](#hybrid-tokens-net-10)
- [Try the demo](#try-the-demo)
- [Public API at a glance](#public-api-at-a-glance)
- [How it fits the PostQuantum.* family](#how-it-fits-the-postquantum-family)
- [Comparison with alternatives](#comparison-with-alternatives)
- [Security posture](#security-posture)
- [Supply chain](#supply-chain)
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

Three honest checks before you adopt this package.

### ✅ Use PostQuantum.Identity when…

- **You ship ASP.NET Core Identity** and want to migrate the password hasher to
  Argon2id with a one-line registration change and zero migration job
  — see [`docs/MIGRATION.md`](docs/MIGRATION.md).
- **You issue JWTs to your own services** and want hybrid (classical + PQ)
  signatures *now*, ahead of the standards landing. You **own both the issuer
  and every verifier** — there is no third-party JWT library in your trust
  chain that needs to understand `alg = ML-DSA-65`.
- **You want a small, focused dependency**: framework-agnostic Identity core,
  Argon2id from a vetted library, ML-DSA / ML-KEM from the BCL. No mystery
  meat, no hand-rolled crypto.

### ⚠️ Use the standalone Argon2id package instead when…

- You **don't ship Identity at all** (a console app, a tool, a non-ASP.NET
  service). Reach for [`Argon2id.PasswordHasher`](https://github.com/systemslibrarian/argon2id-passwordhasher)
  directly — it's a richer Argon2id surface (peppering, a more general
  migration adapter, benchmarks) without the Identity contracts.
- You need **a server-held pepper / keyed hashing**. This package's Argon2id
  core is intentionally salt-and-parameters-only; the standalone package adds
  a `PepperRing` for HSM-style secret mixing.

### ⛔ Don't use PostQuantum.Identity when…

- **You need the issued tokens to validate in third-party JWT tooling**
  (`System.IdentityModel.Tokens.Jwt`, Auth0/Okta SDKs, OIDC providers). The
  `alg = ML-DSA-65` identifier is intentionally non-IANA — the spec hasn't
  landed. Generic libraries will reject these tokens.
- **You're waiting for the .NET PQC story to fully mature.** That's a
  reasonable position to hold; this package exists for people who want to
  shorten the harvest-now-decrypt-later window today, with eyes open, in a
  closed system they fully control.
- **You can't tolerate a preview library.** This is `0.x.y-preview.z`, has
  **not** been independently audited, and the public API may shift before
  1.0. See [`KNOWN-GAPS.md`](KNOWN-GAPS.md) for the honest list of what's
  unfinished or unverified.

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

## Supply chain

The same hygiene we apply to the code applies to the package you install:

- **SBOM in every `.nupkg`.** Every `dotnet pack` emits a CycloneDX SBOM
  (`bom.json`) and embeds it at the root of the package, generated from the
  *multi-target* dependency graph (no TFM collapses to keep transitive deps
  intact). Inspect with `unzip -p PostQuantum.Identity.<v>.nupkg bom.json`.
- **Build provenance attestation.** The
  [`release.yml`](.github/workflows/release.yml) workflow attaches a GitHub
  artifact attestation to every published `.nupkg` / `.snupkg` via
  [`actions/attest-build-provenance`](https://github.com/actions/attest-build-provenance),
  so consumers can verify the package was built from this repo at a specific
  commit with `gh attestation verify`.
- **Deterministic builds with SourceLink.** The repo sets `Deterministic=true`,
  `ContinuousIntegrationBuild=true` under CI, embeds the GitHub repository URL,
  and ships `.snupkg` symbols. Stack traces from a published `.nupkg` map back
  to a known commit in this repo.
- **Pinned dependency surface.** The library depends on:
  - `Konscious.Security.Cryptography.Argon2` (Argon2 1.3 spec impl) — every
    TFM,
  - `Microsoft.Extensions.Identity.Core` (Identity contracts; no web host, no
    EF) — every TFM,
  - `PostQuantum.Jwt` — **net10 only**, gated by `#if NET10_0_OR_GREATER`.

  Dependabot is configured (see `.github/dependabot.yml`) to surface upstream
  bumps as PRs.
- **CodeQL on every PR.** [`codeql.yml`](.github/workflows/codeql.yml) scans
  on every push and pull request; results land in GitHub's Security tab.

How to verify a package you pulled from NuGet:

```bash
# 1. Inspect the embedded SBOM.
nuget install PostQuantum.Identity -Version 0.3.0-preview.1
unzip -p PostQuantum.Identity.0.3.0-preview.1.nupkg bom.json | jq '.components | length'

# 2. Verify the GitHub build-provenance attestation for the same .nupkg.
gh attestation verify PostQuantum.Identity.0.3.0-preview.1.nupkg \
  --owner systemslibrarian
```

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
