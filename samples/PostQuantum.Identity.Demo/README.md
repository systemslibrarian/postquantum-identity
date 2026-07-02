# PostQuantum.Identity demo — minimal API

A **production-shaped** reference application: real ASP.NET Core Identity wired
to PostQuantum.Identity, exercising every flow you would actually use in a
service that issues post-quantum JWTs from passwords.

## What this sample demonstrates

| Flow | Endpoint | What you learn from it |
|------|----------|------------------------|
| **Registration** | `POST /register` | Argon2id password hashing through `IPasswordHasher<TUser>`; validated input via `ProblemDetails`. |
| **Login** | `POST /login` | Constant-time password verification, then issuance of an ML-DSA-65–signed PQ-JWT; no account enumeration leak. |
| **Authenticated `/me`** | `GET /me` (`[Authorize]`) | Token validation through the `PqJwtBearer` handler — fail-closed on tamper / expiry / wrong key. |
| **Refresh** | `POST /refresh` (`[Authorize]`) | Rotate a token before expiry; **revokes the old `jti`** so a stolen near-expiry token can't outlive its replacement. |
| **Logout** | `POST /logout` (`[Authorize]`) | Adds the current `jti` to an in-memory revocation list; the next call with that token returns `401`. |
| **Key rotation** | implicit via `kid` header | Two-key ring (`k1` previous, `k2` current). New tokens are signed with `k2` and stamped with its `kid`; the verifier resolves the right public key by `kid`, so both keys validate. |
| **Public-key discovery** | `GET /.well-known/pq-jwks` | Exposes the ML-DSA-65 verification keys (kid → SPKI) so downstream services can validate independently. |

User data lives in an in-memory EF Core database, so there is nothing to
install. By default the ML-DSA-65 keys are generated at startup for the
lifetime of the process (a demo convenience). For the production-shaped
alternative, set `PQ_ISSUER_KEY_DIR` to a directory of `<kid>.private.pem`
files provisioned by the [KeyTool sample](../PostQuantum.Identity.KeyTool)
(`PQ_ISSUER_KEY_PASSWORD` decrypts encrypted PKCS#8): the issuer signs with
the highest-sorting kid, and verifiers hold only the matching
`*.public.pem` halves — see the
[Verifier demo](../PostQuantum.Identity.Verifier.Demo) for the full
two-service walkthrough.

The revocation list is a `ConcurrentDictionary<string, DateTimeOffset>` (in
memory). A real service would swap that for Redis / a DB table with a TTL
matching the token lifetime; the API contract — "is this `jti` revoked?" — is
the same regardless of the backing store.

## Run

```bash
# Token features need the .NET 10 PQ primitives (OpenSSL 3.5+ on Linux).
# In this dev container, point the loader at conda's OpenSSL:
LD_LIBRARY_PATH=/opt/conda/lib ASPNETCORE_URLS=http://localhost:5199 \
  dotnet run --project samples/PostQuantum.Identity.Demo
```

If ML-DSA is unavailable, the app still runs and hashes passwords; the token
endpoints return `503 Service Unavailable` with a clear `ProblemDetails` body.

Prefer clicking over curl? Open
[`PostQuantum.Identity.Demo.http`](PostQuantum.Identity.Demo.http) in
Visual Studio 2022 or VS Code (REST Client) and run the requests top to
bottom — the token chains between requests automatically, negative cases
included.

## End-to-end walkthrough

```bash
BASE=http://localhost:5199

# 1. Register (password is hashed with Argon2id).
curl -s -X POST $BASE/register \
  -H 'Content-Type: application/json' \
  -d '{"username":"ada","password":"Lovelace#1843"}'

# 2. Log in -> receive a post-quantum hybrid token (ML-DSA-65 signed).
LOGIN=$(curl -s -X POST $BASE/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"ada","password":"Lovelace#1843"}')
TOKEN=$(echo "$LOGIN" | jq -r .token)
echo "kid=$(echo "$LOGIN" | jq -r .kid), exp=$(echo "$LOGIN" | jq -r .expires_in)s"

# 3. Call a protected endpoint -> the token is validated, claims returned.
curl -s $BASE/me -H "Authorization: Bearer $TOKEN" | jq

# 4. Refresh — get a fresh token; the OLD jti is revoked after issuance
# succeeds, so a transient failure never leaves the caller token-less.
REFRESH=$(curl -s -X POST $BASE/refresh -H "Authorization: Bearer $TOKEN")
NEW_TOKEN=$(echo "$REFRESH" | jq -r .token)

# The OLD token now returns 401 (rotated_from is on the revocation list).
curl -s -o /dev/null -w "old token after refresh -> %{http_code}\n" \
  $BASE/me -H "Authorization: Bearer $TOKEN"
curl -s -o /dev/null -w "new token after refresh -> %{http_code}\n" \
  $BASE/me -H "Authorization: Bearer $NEW_TOKEN"

# 5. Logout — explicitly revoke the current token.
curl -s -X POST $BASE/logout -H "Authorization: Bearer $NEW_TOKEN"
curl -s -o /dev/null -w "after logout -> %{http_code}\n" \
  $BASE/me -H "Authorization: Bearer $NEW_TOKEN"

# 6. Public-key discovery — for downstream verifiers.
curl -s $BASE/.well-known/pq-jwks | jq '.keys[] | {kid, alg, kty}'
```

Expected behaviours:

- Wrong password → `401 Unauthorized`.
- Tampered token → `401 Unauthorized` (handler fails closed).
- Token after `/logout` or after the corresponding `/refresh` → `401`.
- Expired token → `401`.
- Empty / malformed JSON body → `400 Bad Request` with an RFC 7807
  `ProblemDetails` payload.

## Wiring at a glance

```csharp
builder.Services
    .AddIdentityCore<IdentityUser>()
    .AddArgon2idPasswordHasher<IdentityUser>(o => o.MemorySizeKib = 19456)
    .AddEntityFrameworkStores<DemoIdentityContext>()
    .AddPostQuantumTokens<IdentityUser>(o =>
    {
        // currentKeyId is "k2" with per-process keys, or the ordinal-highest
        // provisioned kid (e.g. "k-2026-07") in PQ_ISSUER_KEY_DIR mode —
        // zero-pad date-based kids so ordinal order stays chronological.
        o.SigningKey = signingKeyRing[currentKeyId]; // current ML-DSA-65 key
        o.KeyId      = currentKeyId;                 // stamped into kid header
        o.Issuer     = Issuer;
        o.Audience   = Audience;
        o.Lifetime   = TimeSpan.FromHours(1);
    });

builder.Services
    .AddAuthentication(PqJwtBearerDefaults.AuthenticationScheme)
    .AddPqJwtBearer(o => o.ValidationParameters = new PqJwtValidationParameters
    {
        // The kid resolver returns the right public key for the token's kid header.
        SignatureKeyResolver = kid => verifyingKeyRing.GetValueOrDefault(kid ?? ""),
        ValidIssuer = Issuer,
        ValidAudience = Audience,
    });
```

The revocation middleware (post-authentication) checks `jti` against the
in-memory list and short-circuits with `401` for revoked tokens.

---

*To God be the glory — 1 Corinthians 10:31.*
