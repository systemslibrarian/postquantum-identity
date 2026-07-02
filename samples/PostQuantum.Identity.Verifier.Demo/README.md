# PostQuantum.Identity verifier demo — the other half of the deployment model

The library's production stance for hybrid tokens is: *adopt when you own
both the issuer and every verifier*. The
[issuer demo](../PostQuantum.Identity.Demo) shows the issuing half; **this
sample is the verifying half** — a downstream resource service in the same
fleet:

```
┌─────────────────────┐   PQ-JWT (ML-DSA-65)   ┌──────────────────────┐
│ Identity.Demo :5199 │ ──────────────────────>│ Verifier.Demo :5299  │
│ issuer              │                        │ resource service     │
│ passwords, Argon2id │   public keys only     │ NO passwords         │
│ PRIVATE signing keys│ <──── pq-jwks / PEM ───│ NO private keys      │
└─────────────────────┘                        │ NO Identity store    │
                                               └──────────────────────┘
```

## What this sample proves by existing

- **A verifier needs only `PostQuantum.Jwt.AspNetCore` + the issuer's public
  keys.** This project does not reference `PostQuantum.Identity` at all — no
  ASP.NET Core Identity, no user store, no private keys, no passwords.
- **Two key-distribution modes**, both shown in ~40 lines:
  1. **JWKS pull** (default) — fetches the issuer's `/.well-known/pq-jwks`
     at startup, with retries so start-order doesn't matter locally.
  2. **File-based** — set `PQ_VERIFIER_KEY_DIR` (or
     `Verifier:PublicKeyDirectory`) to a directory of `*.public.pem` files
     provisioned by the [KeyTool sample](../PostQuantum.Identity.KeyTool);
     the kid comes from the file name. For fleets where verifiers must not
     depend on the issuer being reachable at boot.
- **Fail-closed startup.** No loadable keys → the host refuses to start,
  rather than starting with an `[Authorize]` surface that can never
  authorize anyone.

Prefer clicking over curl? Open
[`PostQuantum.Identity.Verifier.Demo.http`](PostQuantum.Identity.Verifier.Demo.http)
in Visual Studio 2022 or VS Code (REST Client) — it runs the whole
cross-service flow below, including the revocation-doesn't-cross-services
edge, with the token chaining automatically.

## Run the two-service walkthrough

```bash
# Terminal 1 — the issuer:
ASPNETCORE_URLS=http://localhost:5199 dotnet run --project samples/PostQuantum.Identity.Demo

# Terminal 2 — this verifier (defaults to :5299, pulls pq-jwks from :5199):
dotnet run --project samples/PostQuantum.Identity.Verifier.Demo

# Terminal 3 — a client crossing the service boundary:
curl -s -X POST localhost:5199/register -H 'Content-Type: application/json' \
  -d '{"username":"ada","password":"Lovelace#1843"}'
TOKEN=$(curl -s -X POST localhost:5199/login -H 'Content-Type: application/json' \
  -d '{"username":"ada","password":"Lovelace#1843"}' | jq -r .token)

# The token issued by :5199 is accepted by :5299 — different process,
# different app, no shared code, only the public keys in common.
curl -s localhost:5299/orders -H "Authorization: Bearer $TOKEN" | jq

# Fail-closed at the boundary:
curl -s -o /dev/null -w "no token   -> %{http_code}\n" localhost:5299/orders
curl -s -o /dev/null -w "tampered   -> %{http_code}\n" localhost:5299/orders \
  -H "Authorization: Bearer ${TOKEN%?}x"
```

### PEM-provisioned variant (no JWKS dependency)

```bash
# Provision a fleet key directory once, out of band:
dotnet run --project samples/PostQuantum.Identity.KeyTool -- \
  generate --kid k-2026-07 --out ./fleet-keys --password fleet-pw

# Issuer signs with the newest provisioned kid:
PQ_ISSUER_KEY_DIR=./fleet-keys PQ_ISSUER_KEY_PASSWORD=fleet-pw \
  ASPNETCORE_URLS=http://localhost:5199 \
  dotnet run --project samples/PostQuantum.Identity.Demo

# Verifier holds only the public halves — same directory, *.public.pem only:
PQ_VERIFIER_KEY_DIR=./fleet-keys \
  dotnet run --project samples/PostQuantum.Identity.Verifier.Demo
```

## Honesty notes

- **Revocation does not cross the service boundary.** This verifier checks
  signature + issuer + audience + expiry. A token revoked via the issuer's
  `/logout` still validates *here* until it expires — cross-service
  revocation needs a shared store (Redis / DB) consulted by every verifier.
  Short token lifetimes bound the exposure either way. Also stated in
  [`KNOWN-GAPS.md`](../../KNOWN-GAPS.md).
- **Keys are fetched once at startup.** A production verifier should re-poll
  (or subscribe) so key rotation propagates without a redeploy — the
  rotation procedure in the root README assumes verifiers learn new kids
  before the issuer signs with them.
- The `pq-jwks` document is deliberately *not* claimed to be RFC 7517 JWKS —
  PQC key representation in JOSE is still in IETF drafts. Within an owned
  fleet, the shape you exchange is yours to pin.

---

*To God be the glory — 1 Corinthians 10:31.*
