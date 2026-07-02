# Security Policy

PostQuantum.Identity ships two surfaces with **different maturity profiles**,
and this document is honest about that:

- The **Argon2id password-hashing surface** is implemented to production
  discipline (RFC 9106 KAT-pinned, fail-closed, constant-time tag compare,
  vetted dependency). **Suitable for production adoption today**, on every
  supported runtime (net8 / net9 / net10).
- The **hybrid post-quantum token surface** is production-quality code
  appropriate for **owned / trusted ecosystems** (you control the issuer
  and every verifier) — service-to-service inside one fleet, internal B2B,
  mTLS-bracketed APIs. **Not** appropriate for public-internet OIDC until
  the IETF JOSE PQC drafts land and
  [PostQuantum.Jwt](https://github.com/systemslibrarian/postquantum-jwt)
  picks up the standardized identifiers.

Neither half has been independently audited. The
[`KNOWN-GAPS.md`](KNOWN-GAPS.md) file enumerates everything that is
unfinished, unverified, or deliberately out of scope, and is updated in
lockstep with the code. Read it before depending on this library. The 1.0
version is a **semver commitment** — the public API only breaks with a major
version — not an audit claim; see
[What 1.0 means](README.md#what-10-means--and-what-it-does-not).

## Supported versions

| Version             | Supported           |
|---------------------|---------------------|
| `1.0.x`             | ✅ (current stable)  |
| `0.6.0-preview.*`   | ❌ (superseded)      |
| `0.5.0-preview.*`   | ❌ (superseded)      |
| older previews      | ❌                  |

Only the most recent release on the current stable line receives fixes.

## Reporting a vulnerability

Please report security issues **privately** — do not open a public issue for
an exploitable flaw.

- Use GitHub's **"Report a vulnerability"** (Security → Advisories) on the
  repository, **or**
- email the maintainer listed on the GitHub profile.

Please include a description, affected version, and a reproduction if
possible. We aim to acknowledge within **5 business days**. As an unfunded
open-source project, timelines are best-effort and stated honestly rather
than promised.

## Threat model

**Goals**

- **Password confidentiality at rest.** Stored credentials are Argon2id PHC
  hashes with secure-by-default, memory-hard work factors. A database breach
  does not hand the attacker plaintext passwords.
- **Transparent strengthening.** When work factors are raised, existing hashes
  verify and report `SuccessRehashNeeded`, so Identity upgrades them on the
  next login — no window where old, weaker hashes silently persist as
  "current".
- **Token integrity & authenticity** via ML-DSA-65 signatures (FIPS 204).
- **Confidentiality (optional)** via X-Wing key agreement + AES-256-GCM, where
  the AES key is the X-Wing shared secret. Confidentiality holds unless
  **both** X25519 and ML-KEM-768 are broken.
- **Fail-closed behavior.** Malformed stored hashes never verify. Every token
  validation failure raises. There is no unsigned path and no `alg: none`.
- **Bounded verification cost.** A stored PHC hash declares the work factors
  spent to verify it, so a poisoned row (compromised database, hostile
  import) could otherwise demand an absurd computation — `m=2147483647`
  would be a ~2 TiB allocation attempt on every sign-in against that row.
  The parser enforces acceptance bounds (`m` ∈ [8 KiB, 4 GiB], `t` ∈ [1, 512],
  `p` ∈ [1, 64], `m ≥ 8·p`, salt ∈ [8, 64] bytes, tag ∈ [12, 512] bytes) that
  clear every profile a legitimate encoder emits — reference CLI, libsodium
  up to its "sensitive" 1 GiB profile, all of this library's presets — while
  capping what a hostile row can extract from one call. Out-of-bounds values
  fail closed at parse time, before any allocation.
- **Canonical stored form.** Every accepted hash has exactly one spelling.
  Salt and tag segments must be the single canonical unpadded-base64
  encoding of their bytes (the decoder rejects embedded whitespace and
  non-zero trailing bits that `Convert` would otherwise silently tolerate),
  and numeric fields reject leading-zero aliases (`m=08192` ≠ `m=8192`), so
  distinct stored strings can never alias to the same verifier. Oversized
  base64 fields are rejected on length before any decode work, so the parse
  cost itself is bounded too.
- **Reserved-claim immunity.** User-supplied claims cannot overwrite the seven
  reserved claims (`iss/sub/aud/exp/nbf/iat/jti`); they are filtered server-
  side and a tampered store cannot weaponize them through the issuance path.

**Non-goals / out of scope**

- **Key management & storage.** Generating, protecting, rotating, and
  distributing the ML-DSA signing key (and any X-Wing recipient key) is the
  caller's responsibility. This library never persists key material.
- **Token revocation.** Each token carries a unique `jti` but enforcement of
  a revocation list is the caller's concern. The demo wires an in-memory
  list as a reference; production needs a durable store with a TTL matching
  the token lifetime.
- **Peppering / keyed hashing.** This package's Argon2id core does not apply
  a secret pepper. If you need that, use the standalone
  [`argon2id-passwordhasher`](https://github.com/systemslibrarian/argon2id-passwordhasher)
  package.
- **Replay protection.** `jti` is included in issued tokens but enforcement is
  a property of the validator/replay cache you configure in PostQuantum.Jwt,
  not of this package.
- **Side-channel resistance beyond the underlying primitives.** We rely on the
  constant-time properties of the .NET BCL, BouncyCastle (via PostQuantum.Jwt),
  and Konscious's Argon2id; we add no guarantees of our own beyond using
  `FixedTimeEquals` for the final tag comparison.
- **Standards interoperability of tokens.** Tokens use non-IANA algorithm
  identifiers and are not meant to validate in generic JWT libraries.

## Cryptographic construction

| Role                  | Algorithm     | Source                                  |
|-----------------------|---------------|-----------------------------------------|
| Password hashing      | Argon2id (v19) | Konscious.Security.Cryptography.Argon2 |
| Hash comparison       | constant-time | .NET BCL (`CryptographicOperations.FixedTimeEquals`) |
| Salt generation       | CSPRNG        | .NET BCL (`RandomNumberGenerator`)      |
| Token signature       | ML-DSA-65     | .NET BCL (`MLDsa`), via PostQuantum.Jwt |
| KEM (PQ half)         | ML-KEM-768    | .NET BCL (`MLKem`), via PostQuantum.Jwt |
| KEM (classical half)  | X25519        | BouncyCastle, via PostQuantum.Jwt       |
| Content encryption    | AES-256-GCM   | .NET BCL (`AesGcm`), via PostQuantum.Jwt|

**Argon2id defaults.** 64 MiB memory cost (`m = 65536` KiB), 3 iterations
(`t = 3`), 1 lane (`p = 1`), 16-byte salt, 32-byte tag. These exceed the OWASP
minimum and follow the RFC 9106 second recommended profile. Construction throws
for parameters below the documented minimums (8 MiB / t≥1 / p≥1 / 16-byte salt /
16-byte tag) **and above the documented maximums** (4 GiB / t≤512 / p≤64 /
64-byte salt / 512-byte tag) — the maximums mirror the verifier's acceptance
bounds exactly, so this library can never emit a hash its own `Verify` would
refuse.

## Cryptographic assurance

The Argon2id path is covered by unit tests (round-trip, wrong-password,
fail-closed PHC parsing, rehash detection) **and a multi-layer Known Answer
Test corpus**:

- **RFC 9106 §5.3 reference vector** including the rarely-tested keyed +
  associated-data branches. Proves the underlying compute matches the
  standard.
- **Canonical reference-`argon2`-CLI PHC string** must verify through our
  hasher. Proves PHC parse + Argon2id compute are wire-compatible with the
  standard tooling.
- **Wire-format pin of the PHC emitter** on the same vector. Catches drift in
  segment count, version field, comma-ordering, padding-stripping.
- **Compute-then-format-then-verify roundtrips** across OWASP 2024 minimum,
  the library default / RFC 9106 second profile, a stronger profile, and the
  documented minimum allowed by `Argon2idOptions`.
- **Deterministic generative (fuzz-style) corpus** for the PHC parser —
  thousands of seeded-PRNG cases per run: format/parse roundtrips across the
  full acceptance bounds, structural mutations of valid hashes, and hostile
  random garbage. Pins that parsing never throws, anything accepted is within
  the acceptance bounds, and no mutation of a stored hash ever verifies.
  Fixed seeds make every failure reproducible byte-for-byte.

The hybrid-token path is covered end-to-end against the genuine
`PqJwtValidator`, with:

- **Sign-then-encrypt envelope KAT** — 5-segment compact JWE, outer header
  declares `alg:X-Wing`, `enc:A256GCM`, `cty:JWT`, the inner JWS validates.
- **Roundtrip KAT** — recovered claim values byte-for-byte equal the input
  (sub, name, email, role, custom claims).
- **Structural header / payload KATs** — `typ:JWT`, `alg:ML-DSA-65`, optional
  `kid`; registered claim set with `iat ≤ exp`, lifetime exact, unique
  `jti` per issuance.
- **Multi-role array shape KAT** — single role → string, multiple → array.
- **Reserved-claim override protection** — a user-claim named `sub` cannot
  hijack the subject.
- **Fail-closed corpus** — rejection of expired / wrong-key /
  per-segment-tampered / malformed tokens.

(Token-level cryptographic KATs — ML-DSA, X-Wing, ML-KEM, AES-GCM — live in
PostQuantum.Jwt and its dependencies.)

## Dependency rationale

- **Konscious.Security.Cryptography.Argon2** — a widely used C# implementation
  of the Argon2 1.3 spec. We deliberately did **not** hand-roll Argon2id.
- **Microsoft.Extensions.Identity.Core** — the framework-agnostic Identity
  contracts (`IPasswordHasher<TUser>`, `UserManager<TUser>`, `IdentityBuilder`).
  No web host or EF dependency is pulled into the library.
- **PostQuantum.Jwt** (net10 only) — the hybrid JWT engine. Its own crypto
  dependencies (BouncyCastle for X25519/SHA3-256; BCL for ML-DSA/ML-KEM/AES-
  GCM) are documented in that project's SECURITY.md.

## FIPS 140-3 deployment guidance

PostQuantum.Identity is **not itself a FIPS 140-3 cryptographic module**, nor
does it modify the certification status of any underlying primitive. What
this section explains is how the library's surfaces map onto a FIPS-mode
deployment so you can make an honest call with your compliance team.

### Cryptographic-primitive certification status

| Primitive | Used for | FIPS status (as of 2026-06-03) |
|---|---|---|
| **Argon2id** | Password hashing | **Not FIPS-approved.** Argon2 is not a NIST-published primitive. If your policy requires FIPS-only password verifiers, you'll use a PBKDF2 / Argon2 combination or stay on PBKDF2 — Argon2id sits outside the boundary regardless of who implements it. |
| **ML-DSA-65 (FIPS 204)** | Token signature | **NIST-standardized as FIPS 204** (Aug 2024). The .NET 10 BCL ML-DSA implementation's certification status is **TBD** at Microsoft's side — track [Microsoft's FIPS 140 documentation](https://learn.microsoft.com/dotnet/standard/security/fips-compliance) for the current cert state. |
| **ML-KEM-768 (FIPS 203)** | Hybrid encryption (PQ half) | **NIST-standardized as FIPS 203** (Aug 2024). BCL implementation cert TBD — same tracking as above. |
| **X25519** | Hybrid encryption (classical half) | Not a NIST primitive (it is RFC 7748). The combined X-Wing construction is a hybrid; **the classical half is intentionally outside FIPS.** |
| **AES-256-GCM** | Token content encryption | **FIPS-approved.** The BCL `AesGcm` implementation is part of the FIPS-validated Windows / .NET cryptography boundary on supported platforms. |
| **SHA-2 / SHA-3 family** | Underneath the JWS / KDF paths via PostQuantum.Jwt | **FIPS-approved** for SHA-2; SHA-3 family is FIPS 202. |

### How to deploy under FIPS mode

- **OS-level FIPS mode** must be enabled by the platform (Windows Group
  Policy "FIPS Algorithm Policy", or a Linux distribution's FIPS-mode
  kernel / OpenSSL FIPS provider). This library does not flip that switch
  and cannot opt itself out.
- **.NET FIPS-mode behavior** delegates to the platform crypto provider for
  every primitive marked above as "FIPS-approved" — Argon2id and X25519 do
  not change behavior under FIPS mode because they're outside the boundary
  to start with.
- **What practically breaks** under a strict FIPS-only configuration:
  - The Argon2id surface still **runs** (Konscious is a managed
    implementation), but if your policy forbids non-FIPS-approved
    primitives in production, you can't use this hasher there. Stay on
    `PasswordHasher<TUser>` (PBKDF2) or run an Argon2id deployment outside
    the FIPS boundary.
  - The hybrid token surface needs the BCL ML-DSA / ML-KEM modules to be
    available; on a FIPS-enforced host where those modules aren't yet
    cert-included, `MLDsa.IsSupported` will return `false` and the token
    service fails closed with a 503-equivalent (see the demo's
    null-tokens branch).
  - X25519 (the classical half of X-Wing) is outside the FIPS boundary;
    encryption is unavailable in strict FIPS-only environments.
- **Compliance-friendly deployment pattern:**
  1. Use the **Argon2id hasher only outside the FIPS-required application
     boundary** (e.g. a separate auth service), or
  2. Use this library's `MigratingPasswordHasher` pattern to verify
     existing PBKDF2 hashes and *not* upgrade to Argon2id when FIPS-only is
     required (override the migrating hasher to suppress the
     `SuccessRehashNeeded` signal), or
  3. Restrict the hybrid-token surface to FIPS-approved building blocks
     only (ML-DSA-65 + AES-256-GCM, **without** the X-Wing classical half).
     This is a configuration choice — set `EncryptForRecipient = null`.

### What we promise / what we don't

- We promise the library is **transparent** about which primitives are
  FIPS-approved and which are not (the table above).
- We promise to update this section when Microsoft publishes the BCL
  ML-DSA / ML-KEM FIPS certification status.
- We do **not** promise that the library itself is FIPS-certified — it
  isn't. It's a thin layer over primitives whose certification is set
  upstream.

If your organization needs a formal FIPS validation of this library, that
is a separate engagement; please file a discussion on the repo so we can
track it.

## Supply chain

- **Embedded SBOM.** Every `.nupkg` contains a CycloneDX SBOM (`bom.json`)
  generated across all target frameworks; inspect with
  `unzip -p PostQuantum.Identity.<v>.nupkg bom.json`.
- **Build provenance attestation.** The release workflow attaches a GitHub
  artifact attestation to every published `.nupkg` and `.snupkg`, so
  consumers can verify the package was built from this repo at a specific
  commit:

  ```bash
  gh attestation verify PostQuantum.Identity.<v>.nupkg --owner systemslibrarian
  ```

- **Deterministic, SourceLink-enabled builds.** `Deterministic=true`,
  `ContinuousIntegrationBuild=true` under CI, embedded repository URL, and
  `.snupkg` symbols. Stack traces map back to a known commit.
- **CodeQL** runs on every push and pull request; results land in the
  repository's Security tab.
- **Dependabot** surfaces upstream bumps as PRs.

## Honesty statement

This is software written in the open. **1.0 is an API-stability commitment,
not an audit claim** — it has **not** been independently audited, and the
version number does not change that. If your organization requires a
third-party review before adoption, this library does not yet qualify;
independent review is the top item on the
[post-1.0 roadmap](README.md#what-10-means--and-what-it-does-not).

The Argon2id surface is implemented to production discipline and is
appropriate for production adoption today. The hybrid-token surface is
production-ready for **owned / trusted ecosystems** (where you control
both the issuer and every verifier); it is not appropriate for
public-internet OIDC or any boundary that needs generic-JWT-tooling
interoperability — the `alg = ML-DSA-65` identifier is non-IANA on purpose,
inherited from upstream PostQuantum.Jwt (now 1.0.0 stable), and will become
standards-aligned through a normal upstream version bump when the IETF JOSE
PQC drafts land.

Every limitation is enumerated in [`KNOWN-GAPS.md`](KNOWN-GAPS.md), and the
[post-1.0 roadmap](README.md#what-10-means--and-what-it-does-not) in the
README lists exactly what unblocks each remaining item. Every "missing
thing" exists in the sample code, the docs, or the open issue tracker — not
silently in some private TODO file.

---

*To God be the glory — 1 Corinthians 10:31.*
