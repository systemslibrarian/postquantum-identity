# Threat Model

A STRIDE-style threat model for PostQuantum.Identity. Honest about what the
library mitigates, what it relies on its callers to handle, and what is
explicitly out of scope. Reviewers and security teams should read this in
addition to [`SECURITY.md`](../SECURITY.md) and [`KNOWN-GAPS.md`](../KNOWN-GAPS.md).

This model covers **two surfaces** at different maturity levels — the
production-ready Argon2id password hasher (any owned deployment) and the
production-ready-for-owned-ecosystems hybrid post-quantum token issuer
(service-to-service inside one fleet, internal B2B, mTLS-bracketed APIs).
Threats are listed per surface.

## Assets the library helps protect

| Asset | Where it lives | Whose job is the rest |
|---|---|---|
| **Stored password verifiers** (PHC-formatted Argon2id hashes) | Your Identity user store | DB encryption-at-rest, backups, access control — yours |
| **Token integrity & authenticity** | ML-DSA-65 signature over the JWS payload | Validator deployment, key distribution — yours |
| **Token confidentiality (optional)** | X-Wing (X25519 + ML-KEM-768) + AES-256-GCM envelope | Recipient private-key custody — yours |
| **Signing key custody** | The `MLDsa` instance you pass into `PostQuantumTokenOptions.SigningKey` | KMS / HSM / disk-encrypted store — **always yours** |
| **Algorithm parameter integrity** | The PHC string embeds m/t/p/salt + the token header carries kid | Per-issuance defaults via `Argon2idOptions` / `PostQuantumTokenOptions` |

The library **never persists key material** and never touches your user
store directly.

## Trust boundaries

```
┌──────────────────────────────┐
│  caller's process            │
│                              │
│  ┌────────────────────────┐  │
│  │  PostQuantum.Identity  │  │  ← this library
│  │   - Argon2id hasher    │  │
│  │   - Token service      │  │
│  └────────────────────────┘  │
│         │           │        │
│         │           │        │
│   Konscious     PostQuantum  │  ← native-managed crypto deps
│   Argon2        .Jwt + BCL   │
│                              │
└──────────┬───────────────────┘
           │
       ────┴──── trust boundary ────────
           │
   ┌───────▼────────┐    ┌──────────────┐
   │ Identity store │    │  Verifiers   │
   │ (DB row)       │    │ (your fleet) │
   └────────────────┘    └──────────────┘
```

The library, its direct dependencies, and the consumer's auth code share
one process. Everything past the dashed line is yours to manage.

---

## Surface 1 — Argon2id password hashing

### STRIDE

| Threat | Vector | Mitigation in this library | Residual / caller's job |
|---|---|---|---|
| **S**poofing | Forging a successful sign-in for a user whose hash you've seen | Argon2id requires the *plaintext* to match; PHC parsing is fail-closed on any malformed input; constant-time tag compare via `FixedTimeEquals` | Anti-enumeration / lockout / 2FA — Identity's job, not this library's |
| **T**ampering | Editing a stored hash to weaken its parameters and re-attacking offline | The hash *is* its own verifier — flipping m/t/p in the PHC will simply re-compute under the tampered params and fail to match the stored tag | Row-level access control / DB integrity — yours |
| **R**epudiation | "I didn't set that password" — no audit trail | Out of scope; the hasher takes a plaintext, returns a hash | Caller logs the action with their own audit infra |
| **I**nformation disclosure | Cracking a stolen hash offline | Argon2id is memory-hard (default 64 MiB / t=3) — orders of magnitude more expensive than PBKDF2 against GPU/ASIC attackers. Configurable up to OWASP `HighSecurity()` preset (128 MiB / t=4). Plaintext UTF-8 buffers and computed candidates are zeroed via `CryptographicOperations.ZeroMemory` | Plaintext password lifetime in the caller's process (`string` cannot be zeroed) is yours to minimize |
| **I**nformation disclosure | Side channels (timing, cache) reading verification | Final tag compare is constant-time; the underlying Argon2id is the Konscious library's implementation, with whatever side-channel properties it inherits | Side-channel mitigation beyond constant-time tag compare is not promised |
| **D**enial of service | An attacker spams `/login` to burn server CPU/memory (asymmetric DoS) | Rate-limiter wiring shipped in both samples (`AddRateLimiter` + `RequireRateLimiting("auth")`). `LowMemoryContainer()` preset for memory-constrained hosts | Pair in-process limits with edge limits (CDN/WAF) — yours |
| **D**enial of service | A weak configuration (`m < 8 MiB`) silently shipping to production | `Argon2idOptions.Validate()` enforces a hard floor at construction. `IValidateOptions<Argon2idOptions>` registered in DI fails the host at startup with a message naming the offending property and value | nothing — this one's covered |
| **D**enial of service | A poisoned stored row declaring absurd work factors (`m=2147483647` → ~2 TiB allocation attempt on every verify of that row) | `PhcString.TryParse` enforces acceptance bounds — `m` ∈ [8 KiB, 4 GiB], `t` ∈ [1, 512], `p` ∈ [1, 64], `m ≥ 8·p`, salt ∈ [8, 64] B, tag ∈ [12, 512] B — pinned at both edges of every axis in `PhcStringTests` and swept by the generative corpus. Out-of-bounds fails closed before any allocation | The bounded worst case (one ≤ 4 GiB / ≤ 512-pass computation) is throttled by the same rate limiter that protects `/login` generally — yours to wire (samples show it) |
| **E**levation of privilege | Cross-user confusion via salt/parameter reuse | Salts are fresh `RandomNumberGenerator` bytes per `HashPassword`; the hasher is immutable + thread-safe, with concurrent-correctness regression tests pinning it | nothing — the regression test for distinct concurrent salts is in `Argon2idProductionScenarioTests` |
| **E**levation of privilege | Adversarial PHC string coaxing a verification match | `PhcString.TryParse` is fail-closed on every adversarial input in the regression corpus (variant casing, segment-count, embedded whitespace, base64 attacks, path-traversal noise), and salt/tag segments must be the single canonical unpadded-base64 encoding — whitespace-skipping and non-zero-trailing-bit aliases that `Convert` would tolerate are rejected. A deterministic generative corpus (seeded mutations + hostile garbage, thousands of cases) additionally pins that no mutation of a stored hash ever verifies. `Verify` returns `Failed` on anything that doesn't parse | nothing — pinned |

### Cryptographic correctness assurance

- **RFC 9106 §5.3 Argon2id reference vector** (incl. keyed + AD path) pinned as a KAT.
- **Reference-`argon2`-CLI PHC interop** — a hash produced by the standard CLI verifies through our hasher.
- **PHC emitter wire-format pin** — bytes-for-bytes match against the published vector.
- **Compute → format → verify roundtrips** across OWASP / RFC 9106 / strong / minimum profiles.
- **Per-axis rehash-threshold theory** — every work-factor axis (m/t/p/salt/tag) independently flags rehash.
- **Deterministic generative corpus** (`PhcStringPropertyTests`) — seeded-PRNG roundtrips across the full acceptance bounds, structural mutations of valid hashes, and hostile garbage; pins that parsing never throws, accepted values stay in bounds, and no mutation verifies.
- **Acceptance-bounds edge pin** — both edges of every axis (`m`/`t`/`p`/salt/tag, plus `m ≥ 8·p`) asserted exactly in `PhcStringTests`.

---

## Surface 2 — Hybrid post-quantum tokens (owned ecosystems)

> Suitable for **owned ecosystems** where you control issuer + every
> verifier. Not for public-internet OIDC. See
> [What 1.0 means](../README.md#what-10-means--and-what-it-does-not).

### STRIDE

| Threat | Vector | Mitigation in this library | Residual / caller's job |
|---|---|---|---|
| **S**poofing | Forging a token under a quantum-capable attacker | ML-DSA-65 signature (FIPS 204) — post-quantum-secure under standard assumptions. Token is rejected on any signature failure (fail-closed) | The quantum threat against today's RSA/ECDSA-only systems is exactly what this library hedges against |
| **S**poofing | An `alg: none` injection or `alg` substitution | PostQuantum.Jwt's validator does NOT accept `alg: none` and enforces `alg` per the configured policy. The wire identifier `ML-DSA-65` is intentionally non-IANA so generic JWT libraries cannot accept these tokens either | See "IETF JOSE PQC alignment" in the README for the path forward |
| **T**ampering | Per-segment edit (header / payload / signature) | KAT-pinned: every per-segment tamper is rejected by `PqJwtValidator`. Encryption envelope (when used) is additionally AES-256-GCM, so tamper of ciphertext is rejected by AEAD | nothing — covered |
| **T**ampering | Reserved-claim override via user-store claims (e.g. a `sub` claim in the user's Identity claims) | `PostQuantumTokenService` filters out the seven reserved claims (`iss/sub/aud/exp/nbf/iat/jti`) before writing user claims — covered by a KAT | nothing — covered |
| **R**epudiation | Token replay after compromise | Each token carries a unique `jti`. The samples ship an in-memory revocation list. Production must back it with Redis / a DB table with TTL ≥ token lifetime | Revocation store is yours |
| **I**nformation disclosure | Claim leakage if the token is intercepted in transit | TLS at the transport boundary is your job. Optional X-Wing + AES-256-GCM hybrid encryption (`EncryptForRecipient`) provides end-to-end confidentiality, holding unless **both** X25519 and ML-KEM-768 are broken | TLS, recipient key custody — yours |
| **D**enial of service | Spamming `/login` or `/refresh` to burn ML-DSA signing CPU (asymmetric DoS) | Rate-limiter wiring shipped in both samples on the auth endpoints | Edge-level limits — yours |
| **D**enial of service | A misconfigured `SigningKey` or empty `Issuer/Audience` shipping to production | `IValidateOptions<PostQuantumTokenOptions>` registered in DI — host fails at startup with a message instead of throwing at first `/login` | nothing — covered |
| **E**levation of privilege | A near-expiry token re-used after a refresh | `/refresh` issues the new token first, **then** revokes the old `jti` in the same transaction (regression-tested by the bug-fix commit `5a8e6d7`). Old `jti` lands on the revocation list before the response returns | nothing — covered |
| **E**levation of privilege | Cross-tenant or cross-audience token misuse | `aud` claim is set at issuance and enforced by the validator. Mismatched audience is rejected (KAT) | Pick distinct `Audience` values per tenant — yours |

### Cryptographic correctness assurance

- **JOSE header KAT** — `typ:JWT`, `alg:ML-DSA-65`, optional `kid`.
- **Registered-claim KAT** — `iss/sub/aud/iat/exp/jti` shape + timestamp consistency + unique `jti`.
- **Single-vs-multi-role array shape** KAT.
- **Sign-then-encrypt envelope KAT** — 5-segment JWE, `alg:X-Wing`, `enc:A256GCM`, `cty:JWT`, full validation roundtrip.
- **End-to-end recovered-claim equality** KAT.
- **Fail-closed corpus** — expired / wrong-key / per-segment tamper / malformed tokens, all rejected.

(The cryptographic primitives — ML-DSA, ML-KEM, X25519, AES-GCM — have
their own KATs in PostQuantum.Jwt and its dependencies.)

---

## Explicitly out of scope

These are **NOT** mitigations this library provides; you must address them
in your application or platform.

- **Key generation, distribution, and rotation** of the ML-DSA signing key
  (and any X-Wing recipient key). The library accepts an `MLDsa` instance and
  uses it; it does not generate, persist, or rotate it.
- **Replay protection storage.** The library emits a unique `jti` per token;
  enforcing "this `jti` was seen before" requires a store you wire in
  (PostQuantum.Jwt's replay cache, or your own).
- **Server-held pepper / keyed hashing** for the Argon2id hasher. By design;
  use the standalone [`Argon2id.PasswordHasher`](https://github.com/systemslibrarian/argon2id-passwordhasher)
  if you need a `PepperRing`.
- **Lockout, throttling, anti-enumeration** on sign-in. Memory-hard hashing
  raises the offline cost; online lockout is Identity's job.
- **Transport security (TLS).** The library returns a token string; TLS is
  yours.
- **Database encryption at rest** for the user store.
- **Identity-provider flows (OAuth2 / OIDC / WS-Fed).** This library is
  not an authorization server; it plugs into an existing Identity stack.
- **Cross-ecosystem token verification** (Java / Node / Rust) — pending
  IETF JOSE PQC alignment; see the README.

---

## Review history

| Version | Reviewed by | Date | Outcome |
|---|---|---|---|
| `0.3.0-preview.1` | internal — Paul Clark | 2026-06-02 | Documented; no third-party audit yet |
| `0.5.0-preview.1` | internal — Paul Clark | 2026-06-03 | Re-reviewed; no scope changes; production-readiness polish only |
| `0.6.0-preview.1` | internal | 2026-07-02 | Verify-path hardening: PHC acceptance bounds (poisoned-row DoS), canonicality pins (base64 + numeric), deterministic generative corpus; 7-angle adversarial code review of the changeset |
| `1.0.0` | internal | 2026-07-02 | Upstream PostQuantum.Jwt upgraded to 1.0.0 stable (zero API drift; full suite + samples E2E re-verified); no threat-model scope changes — 1.0 is an API-stability commitment, not a review outcome |

Independent third-party review is the top item on the
[post-1.0 roadmap](../README.md#what-10-means--and-what-it-does-not).

---

*To God be the glory — 1 Corinthians 10:31.*
