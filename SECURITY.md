# Security Policy

PostQuantum.Identity is **preview software** (`0.x.y-preview.z`). It is not yet
suitable for production use and has not been independently audited. This document
states the security model honestly so you can make an informed decision before
relying on it.

## Supported versions

| Version             | Supported           |
|---------------------|---------------------|
| `0.2.0-preview.*`   | ✅ (latest preview)  |
| `0.1.0-preview.*`   | ❌ (superseded)      |
| anything older      | ❌                  |

During the `0.2.0-preview.*` series only the most recent preview receives fixes.

## Reporting a vulnerability

Please report security issues **privately** — do not open a public issue for an
exploitable flaw.

- Use GitHub's **"Report a vulnerability"** (Security → Advisories) on the
  repository, **or**
- email the maintainer listed on the GitHub profile.

Please include a description, affected version, and a reproduction if possible.
We aim to acknowledge within **5 business days**. As an unfunded preview project,
timelines are best-effort and stated honestly rather than promised.

## Threat model

**Goals**

- **Password confidentiality at rest.** Stored credentials are Argon2id PHC
  hashes with secure-by-default, memory-hard work factors. A database breach does
  not hand the attacker plaintext passwords.
- **Transparent strengthening.** When work factors are raised, existing hashes
  verify and report `SuccessRehashNeeded`, so Identity upgrades them on the next
  login — no window where old, weaker hashes silently persist as "current".
- **Token integrity & authenticity** via ML-DSA-65 signatures (FIPS 204).
- **Confidentiality (optional)** via X-Wing key agreement + AES-256-GCM, where
  the AES key is the X-Wing shared secret. Confidentiality holds unless **both**
  X25519 and ML-KEM-768 are broken.
- **Fail-closed behavior.** Malformed stored hashes never verify. Every token
  validation failure raises. There is no unsigned path and no `alg: none`.

**Non-goals / out of scope**

- **Key management & storage.** Generating, protecting, rotating, and
  distributing the ML-DSA signing key (and any X-Wing recipient key) is the
  caller's responsibility. This library never persists key material.
- **Peppering / keyed hashing.** This package's Argon2id core does not apply a
  secret pepper. If you need that, use the standalone
  [`argon2id-passwordhasher`](https://github.com/systemslibrarian/argon2id-passwordhasher)
  package.
- **Replay protection.** `jti` is included in issued tokens but enforcement is a
  property of the validator/replay cache you configure in PostQuantum.Jwt, not of
  this package.
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

## Dependency rationale

- **Konscious.Security.Cryptography.Argon2** — a widely used C# implementation of
  the Argon2 1.3 spec. We deliberately did **not** hand-roll Argon2id.
- **Microsoft.Extensions.Identity.Core** — the framework-agnostic Identity
  contracts (`IPasswordHasher<TUser>`, `UserManager<TUser>`, `IdentityBuilder`).
  No web host or EF dependency is pulled into the library.
- **PostQuantum.Jwt** (net10 only) — the hybrid JWT engine. Its own crypto
  dependencies (BouncyCastle for X25519/SHA3-256; BCL for ML-DSA/ML-KEM/AES-GCM)
  are documented in that project's SECURITY.md.

## Honesty statement

This is preview software written in the open. It has **not** been audited. The
Argon2id path is covered by unit tests (round-trip, wrong-password, fail-closed
parsing, rehash detection). The hybrid-token path is covered by an end-to-end
test that issues a token for an Identity user and validates it with the genuine
`PqJwtValidator`, including a wrong-audience rejection. Until a 1.0 release and an
external review, treat this library as suitable for experimentation only. Known
limitations are tracked transparently in [`KNOWN-GAPS.md`](KNOWN-GAPS.md).

---

*To God be the glory — 1 Corinthians 10:31.*
