# PostQuantum.Identity MVC demo — controllers

The same production-shape Argon2id + post-quantum-token wiring as
[`PostQuantum.Identity.Demo`](../PostQuantum.Identity.Demo), expressed with
attribute-routed **MVC controllers** instead of minimal APIs — for teams whose
codebases are controller-based.

## What this sample demonstrates

| Flow | Endpoint | What you learn from it |
|------|----------|------------------------|
| **Registration** | `POST /account/register` | Argon2id password hashing through `IPasswordHasher<TUser>`; structured validation errors. |
| **Login** | `POST /account/login` | Password verification + ML-DSA-65 PQ-JWT issuance; no account enumeration. |
| **Authenticated `/me`** | `GET /me` (`[Authorize]`) | `PqJwtBearer` validation, fail-closed on tamper / expiry / wrong key. |
| **Refresh** | `POST /account/refresh` (`[Authorize]`) | Rotate before expiry, revoke the old `jti` atomically. |
| **Logout** | `POST /account/logout` (`[Authorize]`) | Add the current `jti` to the revocation list. |

The MVC sample uses a single signing key for simplicity. The minimal-API demo
([`PostQuantum.Identity.Demo`](../PostQuantum.Identity.Demo)) shows the
multi-key ring + `kid`-based rotation pattern, which slots into the controller
sample identically — both samples share the same DI registration shape.

In-memory EF Core store, in-memory revocation list; nothing to install.

## Run

```bash
LD_LIBRARY_PATH=/opt/conda/lib ASPNETCORE_URLS=http://localhost:5202 \
  dotnet run --project samples/PostQuantum.Identity.Mvc.Demo
```

(The `LD_LIBRARY_PATH` is only needed where the system OpenSSL predates 3.5;
password hashing works regardless. Where ML-DSA is unavailable the token
endpoints return `503` with a `ProblemDetails` body.)

## End-to-end walkthrough

```bash
BASE=http://localhost:5202

# 1. Register.
curl -s -X POST $BASE/account/register \
  -H 'Content-Type: application/json' -d '{"username":"ada","password":"Lovelace#1843"}'

# 2. Log in -> receive a PQ-JWT.
LOGIN=$(curl -s -X POST $BASE/account/login \
  -H 'Content-Type: application/json' -d '{"username":"ada","password":"Lovelace#1843"}')
TOKEN=$(echo "$LOGIN" | jq -r .token)

# 3. Protected endpoint.
curl -s $BASE/me -H "Authorization: Bearer $TOKEN" | jq

# 4. Refresh -> new token, old jti revoked.
NEW=$(curl -s -X POST $BASE/account/refresh -H "Authorization: Bearer $TOKEN" | jq -r .token)
curl -s -o /dev/null -w "old after refresh -> %{http_code}\n" \
  $BASE/me -H "Authorization: Bearer $TOKEN"
curl -s -o /dev/null -w "new after refresh -> %{http_code}\n" \
  $BASE/me -H "Authorization: Bearer $NEW"

# 5. Logout.
curl -s -X POST $BASE/account/logout -H "Authorization: Bearer $NEW"
curl -s -o /dev/null -w "after logout -> %{http_code}\n" \
  $BASE/me -H "Authorization: Bearer $NEW"
```

---

*To God be the glory — 1 Corinthians 10:31.*
