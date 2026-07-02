# Quantum readiness for ASP.NET Core Identity apps — a working playbook

A practical, honest sequencing guide for developers who own an ASP.NET Core
Identity application and want to know **what to do about the quantum threat,
in what order, starting now**. No countdown-clock marketing; every claim here
is scoped to what is actually known.

## The threat, scoped honestly

A cryptographically relevant quantum computer (CRQC) running Shor's algorithm
breaks the asymmetric primitives underneath today's auth stacks: **RSA,
ECDSA, ECDH/X25519**. Nobody credible will give you a date; the anchors that
exist are policy, not physics — NIST plans to deprecate classical
public-key algorithms **by 2030** and disallow them **by 2035**
([NIST IR 8547](https://csrc.nist.gov/pubs/ir/8547/ipd)), and the NSA's
CNSA 2.0 timeline pushes national-security systems to post-quantum by the
early 2030s.

Two properties of the threat drive the sequencing below:

1. **"Harvest now, decrypt later" (HNDL) makes confidentiality urgent before
   CRQCs exist.** Traffic and tokens recorded today can be decrypted the day
   the machine arrives. Anything you encrypt *now* whose secrecy must outlive
   that day is already exposed.
2. **Signature forgery only matters once the machine exists.** A recorded
   JWT can't be retroactively forged — but the day signatures fall, every
   system still *verifying* classical signatures falls with them. Signatures
   are a "be migrated before the deadline" problem, not a "your archives are
   already leaking" problem.

Symmetric crypto and hashes are the good news: Grover's algorithm only
halves effective security, so **AES-256, SHA-256/-3, and HMAC are fine** at
the sizes you already use.

## One honest clarification before the checklist

**Argon2id is not post-quantum cryptography.** Password hashing is not
broken by Shor's algorithm; offline cracking economics are (and remain)
classical + GPU/ASIC. Argon2id belongs in this package because a defensible
identity stack needs its *whole* credential path done right, and the stock
PBKDF2 hasher is the weakest link most Identity apps ship today. Upgrading
it is a pure win with zero quantum dependency — which is exactly why it's
step 1. The post-quantum part of this library is the **token surface**
(ML-DSA-65 signatures, optional X-Wing hybrid encryption).

## Inventory: where does asymmetric crypto live in your Identity app?

Walk your deployment and tag each item with *confidentiality-lifetime* (how
long must this stay secret?) and *who verifies it*:

| Asset | Typical primitive today | Quantum exposure | Whose problem |
|---|---|---|---|
| **Stored password hashes** | PBKDF2 | None from Shor — but weak against classical GPU cracking | **This library — fix now** |
| **Access/service tokens (JWT signatures)** | RS256 / ES256 | Forgeable once a CRQC exists; not retroactively | **This library — fix when you own both ends** |
| **Token contents in transit/at rest** | TLS + plaintext JWT payload | HNDL if recorded and payload stays sensitive | This library (optional X-Wing encryption) + your TLS story |
| **TLS itself** | ECDHE key exchange | HNDL — recorded sessions decryptable later | Platform/infra: hybrid key exchange (X25519MLKEM768) is arriving via OS/OpenSSL/CDN updates, **not via a NuGet package** |
| **ASP.NET Core Data Protection** (cookies, antiforgery) | AES + SHA-256 | Fine (symmetric) | Nobody — already quantum-resistant at current sizes |
| **Refresh tokens / API keys stored server-side** | Random strings + hash | Fine if random ≥ 256-bit and hashed | Nobody — keep them random and hashed |
| **Long-lived signed artifacts** (license files, webhooks with year-long validity) | RSA/ECDSA | Must be re-signed or expired before CRQC day | Yours — shorten validity or plan re-signing |

## The sequence

### Step 1 — today, every app: Argon2id for passwords

Zero quantum dependency, pure security win, one line, no migration job:

```csharp
.AddIdentityCore<IdentityUser>()
.AddArgon2idPasswordHasherWithMigration<IdentityUser>()   // rehash-on-login
```

Legacy PBKDF2 hashes keep verifying and upgrade transparently on the next
successful sign-in. Full guide: [`MIGRATION.md`](MIGRATION.md).

### Step 2 — now, if you own both ends: hybrid tokens for service-to-service

If your tokens travel only between services **you deploy** (one fleet,
internal B2B, mTLS-bracketed APIs), you can move their signatures to
ML-DSA-65 today and stop accruing signature-migration debt:

- Provision keys out of band — the
  [KeyTool sample](../samples/PostQuantum.Identity.KeyTool) is the recipe.
- Issue with [`AddPostQuantumTokens`](../README.md#hybrid-tokens-net-10);
  validate with `PqJwtBearer` — the
  [issuer](../samples/PostQuantum.Identity.Demo) and
  [verifier](../samples/PostQuantum.Identity.Verifier.Demo) samples run this
  exact two-service topology.
- If token **payloads** are sensitive and could be recorded in transit
  (HNDL), add `EncryptForRecipient` — X-Wing + AES-256-GCM holds unless
  both X25519 *and* ML-KEM-768 fall.

### Step 3 — wait, deliberately: anything crossing to third-party JWT tooling

Public OIDC, Auth0/Okta integrations, partner APIs validating with generic
JWT libraries: the IETF JOSE PQC identifiers are still drafts, and shipping
placeholder names would create the exact breakage you're trying to avoid.
Keep classical algorithms on those boundaries, keep the token lifetime
short, and track the
[README's JOSE-alignment section](../README.md#ietf-jose-pqc-alignment--where-the-alg-identifier-comes-from)
for when the drafts land.

### Step 4 — in parallel, not in this library: TLS and platform

Hybrid TLS key exchange (X25519MLKEM768) ships through your OS, OpenSSL,
load balancer, and CDN — turn it on as your platform supports it. That is
the primary HNDL mitigation for traffic; nothing a .NET package can do
substitutes for it.

## What "done" looks like

- [ ] Passwords: Argon2id PHC hashes, migration adapter retired once legacy
      hashes have rotated out.
- [ ] Internal tokens: ML-DSA-65 signed, `kid`-based rotation rehearsed
      (not just wired), key custody documented.
- [ ] Sensitive payloads that could be recorded: hybrid-encrypted or
      removed from tokens.
- [ ] External boundaries: consciously classical, with a tracked trigger
      (IETF drafts → RFC) for revisiting.
- [ ] TLS: hybrid key exchange enabled at every terminating hop you control.
- [ ] Long-lived signed artifacts: validity shortened or re-signing planned.

## What this library will not do for you

Key custody (KMS/HSM), TLS, OAuth2/OIDC server flows, cross-service
revocation stores, and platform FIPS posture stay yours — the
[threat model](THREAT-MODEL.md) draws those lines precisely, and
[`KNOWN-GAPS.md`](../KNOWN-GAPS.md) lists every sharp edge. This document is
sequencing advice, not a compliance certificate; the library itself is
unaudited preview software and says so plainly in
[`SECURITY.md`](../SECURITY.md).

---

*To God be the glory — 1 Corinthians 10:31.*
