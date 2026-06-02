# ADR 0001 — Self-contained Argon2id core

- **Status:** Accepted
- **Date:** 2026-06-02

## Context

The author already maintains
[`argon2id-passwordhasher`](https://github.com/systemslibrarian/argon2id-passwordhasher),
a full-featured standalone Argon2id package (peppering, a PBKDF2→Argon2id
migrating hasher, benchmarks). PostQuantum.Identity also needs Argon2id hashing.
The obvious options were (a) depend on that package, or (b) ship a small Argon2id
core here.

## Decision

Ship a **small, self-contained Argon2id core** in PostQuantum.Identity, built
directly on `Konscious.Security.Cryptography.Argon2`, rather than taking a hard
dependency on `argon2id-passwordhasher`.

## Rationale

- **Minimal, predictable dependency graph.** PostQuantum.Identity's reason to
  exist is the *combination* of Argon2id hashing and post-quantum token issuance
  for Identity users. Pulling in a second first-party package — itself preview,
  with its own release cadence and larger surface — would couple two preview
  libraries' versioning for little gain.
- **Focused surface.** We only need hash / verify / rehash-detection + an
  `IPasswordHasher<TUser>` adapter. The richer features (peppering, benchmarks
  baked in) are not required by this package's mission.
- **No capability lost.** Consumers who need peppering or a non-PBKDF2 migration
  source can still use the standalone package; this is documented in
  [`KNOWN-GAPS.md`](../../KNOWN-GAPS.md).

## Consequences

- A small amount of Argon2id/PHC code is duplicated across the two repos. The
  cost is low (the PHC format is stable and well-specified) and is accepted in
  exchange for independence.
- PostQuantum.Identity added its own `MigratingPasswordHasher<TUser>` in
  0.2.0-preview.1 to cover the common PBKDF2 case without the dependency.
