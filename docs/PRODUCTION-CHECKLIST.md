# Production Readiness Checklist

A go-live signoff for teams deploying PostQuantum.Identity into a real
service. Walk this top-to-bottom before flipping production traffic; each
item maps to a code touchpoint, a piece of operational state, or an
explicit caller responsibility.

> **Honest scoping reminder.** The Argon2id password-hashing surface is
> production-ready everywhere. The hybrid post-quantum **token surface** is
> production-ready for **owned / trusted ecosystems** only (you control
> issuer + every verifier) — and the library is unaudited regardless of the
> 1.0 label. If you're shipping the token surface, treat every "token" row
> here as load-bearing — anything you defer will bite later.

---

## 1. Argon2id hasher (the production-ready surface)

- [ ] **Chose a preset that fits your hardware.** `Argon2idOptions.RecommendedDefault()` (64 MiB / t=3) for standard API pods; `OwaspMinimum()` for latency-sensitive endpoints; `HighSecurity()` for admin/KDF paths; `LowMemoryContainer()` for sub-256 MiB pods.
- [ ] **Pod memory budget covers `(per-hash memory) × (concurrent-sign-in budget) + headroom`.** See [Compatibility → Container constraints](../README.md#container-constraints).
- [ ] **Identity policy enforces password requirements** (length, alphabet) at the right strength for your audience. The hasher protects stored verifiers; weak plaintexts still crack.
- [ ] **If migrating an existing store**, registered `AddArgon2idPasswordHasherWithMigration<TUser>` so existing PBKDF2 hashes verify and rewrite on first sign-in. See [`docs/MIGRATION.md`](MIGRATION.md).
- [ ] **Startup validation flips on with the DI helpers.** A misconfigured work factor fails at host startup with a clear message — verified by [`Argon2idStartupValidationTests`](../tests/PostQuantum.Identity.Tests/Argon2idStartupValidationTests.cs).
- [ ] **No bcrypt/scrypt rows left unmigrated**, OR a custom adapter is wired for them. The default migration covers stock PBKDF2 only; see [MIGRATION.md → Migrating from bcrypt/scrypt](MIGRATION.md#migrating-from-bcrypt--scrypt--a-custom-hasher).

## 2. Authentication & sign-in protection

- [ ] **Lockout / throttling configured at the Identity layer** (`UserManager.Options.Lockout`). Argon2id raises the offline cost; lockout addresses online attack and is Identity's job.
- [ ] **Rate limiter on Argon2id-heavy endpoints.** Both samples show the fixed-window IP-partition pattern; ship at least that on `/register`, `/login`, `/refresh`. Tune permits per your traffic profile.
- [ ] **Edge limits (CDN/WAF/API gateway) on the same endpoints.** The in-process limiter is the last line of defense, not the whole story.
- [ ] **Identical `401 Unauthorized` for "no such user" and "wrong password"** so login doesn't leak account enumeration. Both samples do this; double-check your override.
- [ ] **2FA / MFA layered on top** for any privileged user class. Argon2id ≠ MFA.

## 3. Token surface (owned ecosystems only)

- [ ] **Confirmed you own issuer + every verifier.** No third-party JWT tooling in your trust chain needs to understand `alg = ML-DSA-65`. If you can't promise this, skip the token surface entirely until [IETF JOSE PQC alignment](../README.md#ietf-jose-pqc-alignment--where-the-alg-identifier-comes-from) lands.
- [ ] **Signing key is provisioned out of band, NOT generated at app startup** in production. The samples generate per-process for demo simplicity; production needs persistent key custody (KMS, HSM, sealed at-rest).
- [ ] **Verifiers hold only the PUBLIC half** of the ML-DSA-65 key. Use `MLDsa.ImportSubjectPublicKeyInfo(signingKey.ExportSubjectPublicKeyInfo())` to derive verification keys.
- [ ] **`kid` populated on issuance**, and the validator's `SignatureKeyResolver` maps `kid` → public key. This is your rotation contract. Demonstrated in [`PostQuantum.Identity.Demo/Program.cs`](../samples/PostQuantum.Identity.Demo/Program.cs).
- [ ] **Two-key ring deployed** (previous + current), so you can rotate without breaking active tokens. Add the new key with a new `kid`, flip `CurrentKeyId`, wait one `Lifetime`, retire the previous.
- [ ] **`Issuer` and `Audience` are distinct per environment and per tenant.** Mismatched `aud` is rejected by the validator (KAT-pinned).
- [ ] **`Lifetime` matches your traffic pattern.** Default 1 hour is reasonable for most APIs. Shorter = less revocation pressure; longer = more.
- [ ] **Token-options startup validation is wired** — a missing `SigningKey` or empty `Issuer/Audience` fails at host startup. Free with the DI helpers.

## 4. Revocation

- [ ] **`jti` revocation list backed by durable storage** (Redis / DB table with TTL ≥ token lifetime). The samples use in-memory; production must not.
- [ ] **Revocation middleware sits AFTER `UseAuthentication` and BEFORE `UseAuthorization`.** Both samples show the placement.
- [ ] **`/logout` puts the current `jti` on the revocation list.** Idempotent — repeat calls are fine.
- [ ] **`/refresh` issues new token BEFORE revoking old `jti`.** A transient issuance failure must never leave the caller token-less. Demonstrated in both samples; regression-fixed at commit `5a8e6d7`.

## 5. Encryption (optional X-Wing path, only if used)

- [ ] **Recipient X-Wing private key is custody-managed** the same way as the signing key — out of band, persistent, never on disk plaintext.
- [ ] **You actually need confidentiality at the application layer.** TLS at the transport boundary covers most cases; only flip on `EncryptForRecipient` when token contents must remain opaque to intermediaries.
- [ ] **Strict FIPS mode?** X-Wing's classical half is X25519 (non-FIPS). See [`SECURITY.md` → FIPS 140-3 deployment guidance](../SECURITY.md#fips-140-3-deployment-guidance) for the deployment pattern.

## 6. Observability

- [ ] **`/register`, `/login`, `/refresh`, `/logout` produce structured logs** at INFO with the user id (never the password / token) and the outcome.
- [ ] **401 / 429 rates are alertable.** A spike of 429s indicates either an attack or a real-user surge — both warrant a page.
- [ ] **Per-hash latency tracked.** Argon2id should be ~50-200 ms at the recommended preset; sudden swings indicate either a config change or a hardware issue.
- [ ] **`jti` revocation cache hit / miss / evict counts** are visible.

## 7. Supply chain

- [ ] **Pinned an exact version**, not a wildcard. From 1.0.0, semver applies: breaking changes only land with a major version bump — but pin anyway; reproducible deployments beat floating ranges.
- [ ] **`gh attestation verify` runs in your CI pipeline** for the `.nupkg` you're deploying. See [`README.md` → Supply chain](../README.md#supply-chain--verifiable-in-three-commands).
- [ ] **CycloneDX SBOM ingested into your SBOM aggregation tool** if you have one.
- [ ] **Dependabot or equivalent watches** for upstream bumps to `Konscious.Security.Cryptography.Argon2`, `Microsoft.Extensions.Identity.Core`, and (net10) `PostQuantum.Jwt`.

## 8. Disaster recovery

- [ ] **Signing key backed up to a separate failure domain** from your running fleet.
- [ ] **Key compromise runbook written**: revoke kid in the validator's resolver, rotate to a new kid, force re-login (or shorten lifetime to zero out the window), forensics. Test the runbook.
- [ ] **Password-store breach runbook written**: force-reset on next sign-in (`SecurityStamp` rotation is Identity-native), audit access logs, communicate per policy.
- [ ] **Verified migration is reversible** until a user has signed in once (see [`MIGRATION.md` → Rolling back](MIGRATION.md#rolling-back)). After that, Argon2id stays.

## 9. Compliance

- [ ] **FIPS posture reviewed against [`SECURITY.md` → FIPS 140-3 deployment guidance](../SECURITY.md#fips-140-3-deployment-guidance)** with your compliance team. Argon2id is outside the FIPS boundary; this may or may not matter for your jurisdiction.
- [ ] **Threat model in [`docs/THREAT-MODEL.md`](THREAT-MODEL.md) reviewed** and any unmitigated residual items have an owner / a ticket / a deadline.
- [ ] **[`KNOWN-GAPS.md`](../KNOWN-GAPS.md) read end-to-end.** Anything that turns out to be load-bearing for your deployment is a build decision, not a deploy decision.

## 10. Signoff

- [ ] **Test suite green on your CI** (`dotnet test -c Release`).
- [ ] **All TFMs you ship pass** (net8 / net9 / net10 as appropriate).
- [ ] **Sample exercise reproduced** against a real DB-backed store (not the in-memory EF demo). Register → login → /me → refresh → logout → revocation enforced → JWKS exposes only public halves.

If every box is checked, ship. If even one is open and undocumented, the
answer is "not yet."

---

*To God be the glory — 1 Corinthians 10:31.*
