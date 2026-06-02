# ADR 0002 — Hybrid tokens gated to .NET 10

- **Status:** Accepted
- **Date:** 2026-06-02

## Context

The package multi-targets `net8.0;net9.0;net10.0`. The post-quantum token
features depend on the BCL primitives `System.Security.Cryptography.MLDsa` /
`MLKem` and on the `PostQuantum.Jwt` package — all of which ship for **.NET 10
only**. We could (a) not multi-target at all (net10 only), (b) multi-target but
fail at runtime on older TFMs, or (c) multi-target and gate the token surface.

## Decision

Multi-target all three TFMs, but **compile the token surface only on net10.0**,
behind `#if NET10_0_OR_GREATER` and a conditional `<PackageReference>` for
`PostQuantum.Jwt`. The Argon2id password-hashing surface — which has no such
dependency — is available on every TFM.

## Rationale

- **Adopt what works, where it works.** Many teams are still on net8/net9 LTS.
  They can use the Argon2id hasher today; the token features become available
  when they move to net10. Nothing is broken or stubbed at runtime.
- **Honest packaging.** The NuGet dependency groups reflect reality: net8/net9
  depend on Konscious + Identity.Core; net10 additionally depends on
  PostQuantum.Jwt. (Preserving these per-TFM groups drove the SBOM tooling fix —
  see ADR-adjacent note in the csproj.)
- **No false promises.** ML-DSA/ML-KEM are genuinely unavailable before net10;
  pretending otherwise (option b) would be a fail-open trap.

## Consequences

- Two-tier capability matrix, documented in the README and `KNOWN-GAPS.md`.
- `#if` blocks and a conditional package reference add a little build complexity,
  validated by the multi-TFM test matrix.
- The CI matrix must include net8/net9 runtimes (not just the net10 SDK) to run
  the hasher tests on those TFMs.
