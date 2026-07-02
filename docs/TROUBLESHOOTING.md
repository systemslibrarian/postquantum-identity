# Troubleshooting

Symptom → cause → fix, for everything adopters actually hit. Each entry
quotes the real error text where there is one, so this page is greppable.

## Token surface

### Token endpoints return 503 / `MLDsa.IsSupported` is `false`

**Cause:** the .NET 10 BCL post-quantum primitives need OS crypto support —
Windows CNG (Windows 11 / Server 2022+) or OpenSSL 3.5+ **in the 3.x
series** on Linux. On a distro whose system OpenSSL is 3.0.x–3.4.x, ML-DSA
is unavailable and the library fails closed (503 with `ProblemDetails`)
instead of downgrading. **OpenSSL 4.x does not help**: the BCL binds
`libcrypto.so.3`, so against 4.0.1 `MLDsa.IsSupported` is still `false`
(observed in this repo's own CI when conda-forge started resolving
`openssl>=3.5` to 4.x).

**Fix:** point the loader at an OpenSSL 3.5+ (3.x) build, e.g. from
conda-forge (`conda install "openssl>=3.5,<4"`):

```bash
LD_LIBRARY_PATH=/opt/conda/lib dotnet run   # or dotnet test
```

Password hashing is unaffected either way — Argon2id is pure managed code.
The per-OS support matrix is in the
[README's Compatibility section](../README.md#per-os--per-runtime-support).

### `401` with a token that "looks valid"

Work through these in order — the validator is fail-closed, so *any* one of
them is sufficient:

1. **`kid` not resolvable.** The verifier's `SignatureKeyResolver` returned
   `null` for the token's `kid` header. Typical after a key rotation where
   the issuer flipped to a new `kid` before every verifier learned it —
   step 2 of the rotation procedure in the README exists precisely for this.
   Check `GET /.well-known/pq-jwks` (or your provisioned `*.public.pem`
   directory) against the `kid` in the token header.
2. **Issuer or audience mismatch.** `ValidIssuer` / `ValidAudience` must
   byte-match what the issuer stamped. Watch trailing slashes.
3. **Expired.** Default demo lifetime is 1 h; the validator does not add
   grace.
4. **Revoked `jti`** — if you wired the revocation middleware, a `/logout`
   or `/refresh` put this token's `jti` on the list. That's the feature.
5. **Tampered / re-encoded.** Any byte change in any segment fails the
   ML-DSA-65 signature check. There is no "close enough".

### A generic JWT library (jwt.io, `System.IdentityModel.Tokens.Jwt`, Auth0 SDK) rejects the token

**Cause:** by design. `alg = ML-DSA-65` is deliberately non-IANA until the
IETF JOSE PQC drafts settle, so generic tooling refuses it rather than
half-validating it.

**Fix:** validate with `PostQuantum.Jwt.AspNetCore`'s `AddPqJwtBearer` (or
`PqJwtValidator` directly). If a third party must validate your tokens,
you're in the "wait, deliberately" case of the
[quantum-readiness playbook](QUANTUM-READINESS.md#step-3--wait-deliberately-anything-crossing-to-third-party-jwt-tooling)
— keep that boundary classical for now.

### `… is encrypted — set PQ_ISSUER_KEY_PASSWORD.`

The issuer demo found a KeyTool-provisioned `*.private.pem` that is
encrypted PKCS#8. Export the password into `PQ_ISSUER_KEY_PASSWORD` (or
re-provision without `--password`, which the KeyTool warns about — don't).

## Password hashing

### Host fails at startup: `Argon2idOptions misconfigured: MemorySizeKib = 1024 …`

**Cause:** intended behavior. The DI helpers register an
`IValidateOptions<Argon2idOptions>` so a configuration outside the safe
range (below 8 MiB / above 4 GiB, `t` outside [1, 512], `p` outside [1, 64],
salt outside [16, 64] B, tag outside [16, 512] B) boot-fails visibly instead
of surprising a real sign-in.

**Fix:** use a [preset](../README.md#one-line-opinionated-presets)
(`RecommendedDefault` / `OwaspMinimum` / `HighSecurity` /
`LowMemoryContainer`) or bring the named property into range. The failure
message includes the offending property and value on purpose.

### `AddArgon2idPasswordHasher<X> was called on an IdentityBuilder configured for Y`

**Cause:** the `TUser` on the hasher registration doesn't match the one in
`AddIdentityCore<TUser>()`.

**Fix:** pass the same user type in both places. The check exists so you get
this message at registration instead of a confusing
`IPasswordHasher<Wrong>` resolution failure at first sign-in.

### Login latency spiked / container OOM-killed under concurrent sign-ins

**Cause:** Argon2id allocates its memory cost **per call** (64 MiB each with
the default profile), and concurrent sign-ins multiply it.

**Fix:** size pod memory as
`(per-hash memory) × (concurrent sign-in budget) + headroom`, cap the
budget with the rate-limiter pattern both demos wire, and use
`LowMemoryContainer()` (16 MiB, t=4) on tight pods. Sizing table:
[README → Container constraints](../README.md#container-constraints).

### Users can't log in after upgrading this package (correct passwords rejected)

**Cause:** verification acceptance bounds were added (see below). Earlier
versions had no upper work-factor limits, so a config like
`DegreeOfParallelism = Environment.ProcessorCount` on a >64-core host, or
`Iterations > 512`, legally produced stored hashes that the new parser now
rejects — and rejection is indistinguishable from a wrong password. Because
rehash-on-login requires a successful verify first, there is **no automatic
recovery**.

**Fix:** audit whether any historical `Argon2idOptions` config exceeded the
current ceilings (m > 4 GiB, t > 512, p > 64, salt > 64 B, tag > 512 B). If
yes, affected users need a password reset (or stay on the previous package
version until you've run one). If your *current* config is out of range,
startup validation will refuse to boot — treat that error as this tripwire,
not as a value to silently lower.

### Hashes imported from another system won't verify

Check, in order:

1. **Variant:** only `$argon2id$` verifies. `$argon2i$` / `$argon2d$` are
   rejected (different algorithms, not equivalent security).
2. **Version:** only `v=19` (Argon2 1.3). `v=16` hashes need a legacy
   adapter.
3. **Acceptance bounds:** verification accepts `m` ∈ [8 KiB, 4 GiB],
   `t` ∈ [1, 512], `p` ∈ [1, 64] (with `m ≥ 8·p`), salt ∈ [8, 64] B,
   tag ∈ [12, 512] B. Every mainstream encoder profile fits; the bounds
   exist so a poisoned row can't demand a ~2 TiB allocation at verify time
   (see [`SECURITY.md`](../SECURITY.md#threat-model)). There is no override.
4. **Canonical encoding:** every accepted hash has exactly one spelling —
   salt/tag segments must be canonical unpadded base64 (embedded whitespace,
   `=`, or non-zero trailing bits are rejected), and numeric fields must not
   carry leading zeros (`m=08192` is rejected). Re-encode with a
   spec-compliant encoder.
5. **Different scheme entirely** (bcrypt, scrypt, PBKDF2-in-another-format):
   use `MigratingPasswordHasher` with your own legacy adapter — the
   ten-line shape is in
   [`MIGRATION.md`](MIGRATION.md#migrating-from-bcrypt--scrypt--a-custom-hasher).

### Legacy hashes aren't upgrading to Argon2id

**Cause:** rehash-on-login only fires on a **successful** sign-in that flows
through `UserManager` (e.g. `CheckPasswordSignInAsync` /
`CheckPasswordAsync` + the store update). Verifying through a raw
`IPasswordHasher` call never rewrites anything.

**Fix:** confirm sign-ins go through Identity's user manager, and that the
registration is `AddArgon2idPasswordHasherWithMigration`. Wrong passwords
deliberately never trigger a rewrite.

### Binding work factors from `appsettings.json` seems ignored

Binding works — the registration honors a prior `Configure` call — but the
inline lambda/preset overloads *also* call `Configure`, and **last
registration wins** for the same property. Bind like this and drop the
inline values:

```csharp
builder.Services.Configure<Argon2idOptions>(
    builder.Configuration.GetSection("Argon2id"));
builder.Services
    .AddIdentityCore<IdentityUser>()
    .AddArgon2idPasswordHasher<IdentityUser>();   // no inline options
```

```json
{ "Argon2id": { "MemorySizeKib": 131072, "Iterations": 4 } }
```

Add `AddPostQuantumPreflightLogging()` to print the *resolved* values at
boot — that one INFO line settles "what did it actually pick up" instantly.

## Samples & local dev

### `429 Too Many Requests` while scripting against the demos

The demos rate-limit `/register`, `/login`, and `/refresh` to 10 requests
per 30 s per IP — deliberately, as the asymmetric-DoS pattern worth copying.
Slow the loop down or raise `PermitLimit` locally.

### Verifier demo refuses to start: `No verification keys could be loaded …`

**Cause:** fail-closed startup. The issuer wasn't reachable for the
`pq-jwks` pull (it retries 5× over ~10 s), or `PQ_VERIFIER_KEY_DIR` has no
`*.public.pem` files.

**Fix:** start the issuer on `:5199` first (or point `Verifier:JwksUrl` at
it), or provision the directory with the
[KeyTool sample](../samples/PostQuantum.Identity.KeyTool). A verifier that
cannot verify must not start — that behavior is the sample teaching, not a
bug.

### Tests skip on Linux with an ML-DSA reason

Correct and intended: crypto tests that can't run **skip with a reason**
rather than silently passing. To run the full suite where system OpenSSL
predates 3.5: `LD_LIBRARY_PATH=/opt/conda/lib dotnet test`. The CI
"PQ-required" lane pins OpenSSL 3.5+ and fails on any skip, so green CI
means the whole suite genuinely ran somewhere.

---

Hit something not listed? That's a gap by this project's own definition —
please open an issue so it gets recorded honestly.

---

*To God be the glory — 1 Corinthians 10:31.*
