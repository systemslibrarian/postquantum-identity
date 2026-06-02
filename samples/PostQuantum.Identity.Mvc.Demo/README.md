# PostQuantum.Identity MVC demo

The same Argon2id + post-quantum-token wiring as
[`PostQuantum.Identity.Demo`](../PostQuantum.Identity.Demo), expressed with
attribute-routed **MVC controllers** instead of minimal APIs — for teams whose
codebases are controller-based.

- `AccountController` — `POST /account/register`, `POST /account/login`
- `MeController` — `GET /me`, protected with `[Authorize]` via the `PqJwtBearer`
  authentication handler

In-memory EF Core store; nothing to install.

## Run

```bash
LD_LIBRARY_PATH=/opt/conda/lib ASPNETCORE_URLS=http://localhost:5202 \
  dotnet run --project samples/PostQuantum.Identity.Mvc.Demo
```

(The `LD_LIBRARY_PATH` is only needed where the system OpenSSL predates 3.5;
password hashing works regardless.)

## Try it

```bash
curl -s -X POST localhost:5202/account/register \
  -H 'Content-Type: application/json' -d '{"username":"ada","password":"Lovelace#1843"}'

TOKEN=$(curl -s -X POST localhost:5202/account/login \
  -H 'Content-Type: application/json' -d '{"username":"ada","password":"Lovelace#1843"}' | jq -r .token)

curl -s localhost:5202/me -H "Authorization: Bearer $TOKEN"
```

---

*To God be the glory — 1 Corinthians 10:31.*
