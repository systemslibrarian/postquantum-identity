# Security Policy

PostQuantum.Identity ships two surfaces with **different maturity profiles**,
and this document is honest about that:

- The **Argon2id password-hashing surface** is implemented to production
  discipline (RFC 9106 KAT-pinned, fail-closed, constant-time tag compare,
  vetted dependency). It is suitable for production adoption today.
- The **hybrid post-quantum token surface** is preview, appropriate for
  **owned / trusted ecosystems** (you control issuer and every verifier),
  not for public-internet OIDC. It depends on
  [PostQuantum.Jwt](https://github.com/systemslibrarian/postquantum-jwt)
  while that package and the IETF JOSE PQC drafts mature.

Neither half has been independently audited. The
[`KNOWN-GAPS.md`](KNOWN-GAPS.md) file enumerates everything that is
unfinished, unverified, or deliberately out of scope, and is updated in
lockstep with the code. Read it before depending on this library.

## Supported versions

| Version             | Supported           |
|---------------------|---------------------|
| `0.3.0-preview.*`   | ✅ (latest preview)  |
| `0.2.0-preview.*`   | ❌ (superseded)      |
| `0.1.0-preview.*`   | ❌ (superseded)      |
| anything older      | ❌                  |

During the `0.3.0-preview.*` series only the most recent preview receives fixes.

## Reporting a vulnerability

Please report security issues **privately** — do not open a public issue for
an exploitable flaw.

- Use GitHub's **"Report a vulnerability"** (Security → Advisories) on the
  repository, **or**
- email the maintainer listed on the GitHub profile.

Please include a description, affected version, and a reproduction if
possible. We aim to acknowledge within **5 business days**. As an unfunded
preview project, timelines are best-effort and stated honestly rather than
promised.

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
16-byte tag).

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

This is preview software written in the open. It has **not** been
independently audited.

The Argon2id surface is implemented to production discipline and is
appropriate for production adoption today. The hybrid-token surface is the
right tool for **owned / trusted ecosystems** (where you control both the
issuer and every verifier) and is not appropriate for public-internet OIDC
or any boundary that needs generic-JWT-tooling interoperability — the
`alg = ML-DSA-65` identifier is non-IANA on purpose.

Until a 1.0 release and an external review, every limitation is enumerated
in [`KNOWN-GAPS.md`](KNOWN-GAPS.md) and the
[`Roadmap to 1.0`](README.md#roadmap-to-10) in the README lists exactly what
unblocks each remaining gate. Every "missing thing" exists in the sample
code, the docs, or the open issue tracker — not silently in some private
TODO file.

---

*To God be the glory — 1 Corinthians 10:31.*
