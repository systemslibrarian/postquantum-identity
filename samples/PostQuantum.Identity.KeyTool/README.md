# PostQuantum.Identity key tool

The concrete answer to the docs' "provision an ML-DSA-65 key out of band"
step. A tiny console tool — **pure .NET 10 BCL, zero dependencies** — that
generates and inspects ML-DSA-65 signing keys in standard container formats,
so the issuer/verifier split has a real provisioning story instead of a
hand-wave.

## Commands

```bash
# Generate a key pair. Date-based kids make rotation windows self-documenting —
# zero-pad the month/day (k-2026-07, not k-2026-7): the issuer demo signs with
# the ordinal-HIGHEST kid, and only zero-padded names sort chronologically.
dotnet run -- generate --kid k-2026-07 --out ./keys --password s3cret
#   -> ./keys/k-2026-07.private.pem   PKCS#8, AES-256-CBC + PBKDF2-SHA256 (600k iterations)
#   -> ./keys/k-2026-07.public.pem    SubjectPublicKeyInfo — the half verifiers hold

# Inspect either half (algorithm + SPKI SHA-256 fingerprint).
dotnet run -- inspect ./keys/k-2026-07.public.pem
dotnet run -- inspect ./keys/k-2026-07.private.pem --password s3cret
```

Without `--password` the private key is written as plaintext PKCS#8 and the
tool warns loudly. It also refuses to overwrite an existing kid — rotation
means *adding* a key, never replacing one in place (replacing would strand
every token already issued under that kid).

## How it composes with the other samples

```
KeyTool                        issuer demo (:5199)              verifier demo (:5299)
generate --kid k-2026-07  →    PQ_ISSUER_KEY_DIR=./keys    →    PQ_VERIFIER_KEY_DIR=./keys
        ./keys/                PQ_ISSUER_KEY_PASSWORD=…         (reads *.public.pem only)
                               (reads *.private.pem,
                                signs with newest kid)
```

The [issuer demo](../PostQuantum.Identity.Demo) loads `*.private.pem` files
from `PQ_ISSUER_KEY_DIR` and signs with the highest-sorting kid; the
[verifier demo](../PostQuantum.Identity.Verifier.Demo) loads the matching
`*.public.pem` files from `PQ_VERIFIER_KEY_DIR`. Together the three samples
demonstrate the full owned-ecosystem key lifecycle: provision → issue →
verify → rotate.

## Honesty notes

- **PEM-on-disk is the floor, not the goal.** Prefer a KMS / HSM / secret
  store where you have one. This tool exists because every deployment needs
  *some* provisioning step, and "out of band" is not a recipe.
- The tool never prints private-key material and zeroes the PKCS#8 buffer
  after writing — but the file itself is only as safe as its ACLs. Restrict
  them (`chmod 600` / `icacls`) and treat it like any other credential.
- ML-DSA support requires the .NET 10 BCL post-quantum primitives (Windows
  CNG on Windows 11 / Server 2022+, OpenSSL 3.5+ on Linux). The tool exits
  with a clear message where they're unavailable.

---

*To God be the glory — 1 Corinthians 10:31.*
