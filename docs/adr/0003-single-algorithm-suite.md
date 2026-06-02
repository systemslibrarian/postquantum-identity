# ADR 0003 — Single algorithm suite, no agility

- **Status:** Accepted
- **Date:** 2026-06-02

## Context

Identity hashing could expose multiple algorithms (bcrypt/scrypt/Argon2 variants)
and the token layer could expose algorithm agility (ML-DSA-44/65/87, ML-KEM
sizes, alternate AEADs). Agility is sometimes desirable for crypto-migration, but
it also enlarges the attack surface and the test matrix, and invites downgrade
mistakes.

## Decision

Expose a **single, opinionated suite**:

- **Password hashing:** Argon2id only (work factors are tunable; the *algorithm*
  is not).
- **Tokens:** whatever `PostQuantum.Jwt` fixes — ML-DSA-65 signatures, optional
  X-Wing (X25519 + ML-KEM-768) + AES-256-GCM. No `alg` negotiation here.

## Rationale

- **Fewer ways to be wrong.** A single suite means no downgrade path, no "which
  algorithm produced this?" ambiguity beyond what the self-describing PHC string
  and the JOSE header already encode.
- **Secure defaults over knobs.** Argon2id is the current best-practice password
  hash; ML-DSA-65 + X-Wing is a defensible, standards-aligned hybrid. Most callers
  should not be choosing primitives.
- **Smaller, more testable surface** — consistent with the project's "keep the
  surface small" rule.

## Consequences

- No in-library crypto-agility. If a future standard or break requires a new
  suite, it will be introduced deliberately (new ADR), not via a runtime knob.
- Work-factor tuning remains available for Argon2id because raising cost over time
  is a normal, safe operation (existing hashes still verify and self-upgrade).
