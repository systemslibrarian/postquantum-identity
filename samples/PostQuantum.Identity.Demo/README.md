# PostQuantum.Identity demo

A minimal-API ASP.NET Core app showing **real** ASP.NET Core Identity wired to
PostQuantum.Identity:

- **Argon2id** password hashing (`AddArgon2idPasswordHasher<IdentityUser>`)
- **Post-quantum hybrid token** issuance (`AddPostQuantumTokens<IdentityUser>`)
- Token **validation through the `PqJwtBearer` authentication handler** — the
  `/me` endpoint is `[Authorize]`'d, not validated by hand
- **`kid`-based key rotation** — a two-key ring (`k1` previous, `k2` current);
  new tokens are signed with `k2` and stamped with its `kid`, and the verifier
  resolves the right public key by `kid`, so both keys validate

User data is stored in an in-memory EF Core database, so there is nothing to
install. The ML-DSA-65 keys are generated at startup for the lifetime of the
process (a demo convenience — real systems provision and rotate keys out of band,
and verifiers hold only the public halves).

## Run

```bash
# Token features need the .NET 10 PQ primitives (OpenSSL 3.5+ on Linux).
# In this dev container, point the loader at conda's OpenSSL:
LD_LIBRARY_PATH=/opt/conda/lib ASPNETCORE_URLS=http://localhost:5199 \
  dotnet run --project samples/PostQuantum.Identity.Demo
```

If ML-DSA is unavailable, the app still runs and hashes passwords; the token
endpoints return `503` with a clear message.

## Try it

```bash
# 1. Register (password is hashed with Argon2id)
curl -s -X POST localhost:5199/register \
  -H 'Content-Type: application/json' \
  -d '{"username":"ada","password":"Lovelace#1843"}'

# 2. Log in -> receive a post-quantum hybrid token (ML-DSA-65 signed)
TOKEN=$(curl -s -X POST localhost:5199/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"ada","password":"Lovelace#1843"}' | jq -r .token)

# 3. Call a protected endpoint -> the token is validated, claims returned
curl -s localhost:5199/me -H "Authorization: Bearer $TOKEN"
```

Expected `/me` response:

```json
{
  "subject": "<user-id>",
  "name": "ada",
  "issuer": "https://demo.postquantum-identity.local",
  "expiresAt": "..."
}
```

A wrong password returns `401`; a tampered token returns `401` (fail-closed).

---

*To God be the glory — 1 Corinthians 10:31.*
