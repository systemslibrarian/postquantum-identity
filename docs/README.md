# Documentation

Design notes and pointers for PostQuantum.Identity.

## Start here

- [Project README](../README.md) — overview, install, usage, API table.
- [QUANTUM-READINESS.md](QUANTUM-READINESS.md) — what to do about the quantum threat, in what order, for Identity apps.
- [TROUBLESHOOTING.md](TROUBLESHOOTING.md) — symptom → cause → fix for everything adopters actually hit.
- [MIGRATION.md](MIGRATION.md) — moving an existing store from PBKDF2 to Argon2id.
- [SUPPLY-CHAIN.md](SUPPLY-CHAIN.md) — auditor-facing independent verification guide.
- [THREAT-MODEL.md](THREAT-MODEL.md) — STRIDE per surface with per-threat code/test pointers.
- [SECURITY-REVIEW-CHECKLIST.md](SECURITY-REVIEW-CHECKLIST.md) — auditor index to every claim with file/line/test backings.
- [PRODUCTION-CHECKLIST.md](PRODUCTION-CHECKLIST.md) — go-live signoff checklist.
- [Architecture Decision Records](adr/) — why the library is shaped the way it is.
- [SECURITY.md](../SECURITY.md) — threat model and cryptographic construction.
- [KNOWN-GAPS.md](../KNOWN-GAPS.md) — honest list of what is not done yet.
- [CONTRIBUTING.md](../CONTRIBUTING.md) — how to build, test, and submit changes.
- [CLAUDE.md](../CLAUDE.md) — repository conventions.

## Design notes

### Why a self-contained Argon2id core?

PostQuantum.Identity ships its own small Argon2id core (over
`Konscious.Security.Cryptography.Argon2`) rather than depending on the sibling
[`argon2id-passwordhasher`](https://github.com/systemslibrarian/argon2id-passwordhasher)
package. This keeps the dependency graph minimal and the surface focused on the
two things this package exists to do — hash Identity passwords with Argon2id and
issue post-quantum tokens for Identity users. The sibling package remains the
right choice when you need peppering, an in-place PBKDF2→Argon2id migrating
hasher, or benchmarks. See [KNOWN-GAPS.md](../KNOWN-GAPS.md).

### Why is token issuance .NET 10 only?

The post-quantum primitives (`MLDsa`, `MLKem`) live in the .NET 10 BCL, and
PostQuantum.Jwt targets .NET 10. Rather than fork the token surface onto older
runtimes (where it could not work), the token code is gated behind
`#if NET10_0_OR_GREATER` and a conditional package reference. The Argon2id hasher
— which has no such dependency — is available on `net8.0`, `net9.0`, and
`net10.0`.

### PHC string format

Hashes are stored as
`$argon2id$v=19$m=<KiB>,t=<iters>,p=<lanes>$<base64 salt>$<base64 hash>`, with
salt and hash Base64-encoded **without** padding (the PHC convention). Because
every hash carries its own parameters, raising the configured work factors never
invalidates existing hashes — they verify, and `Verify` reports `NeedsRehash` so
Identity upgrades them on next login.

---

*To God be the glory — 1 Corinthians 10:31.*
