# Contributing to PostQuantum.Identity

Thanks for your interest! This is a small, security-focused library, so the bar
for changes is deliberately high — and the conventions are strict. Please read
[`CLAUDE.md`](CLAUDE.md) (the repository conventions) before opening a PR.

## Ground rules

- **Honesty over polish.** If a change is incomplete, unproven, or risky, say so
  — in the PR, in code comments, and in [`KNOWN-GAPS.md`](KNOWN-GAPS.md). Never
  overstate what the cryptography provides.
- **Fail-closed, always.** A malformed stored hash must never verify; token
  validation must throw on any failure. No silent downgrade.
- **Don't roll your own crypto.** Argon2id comes from Konscious; ML-DSA / ML-KEM
  from the .NET BCL via PostQuantum.Jwt. New crypto primitives are out of scope.
- **Keep the surface small.** No speculative features. A new public API or a new
  third-party dependency needs a written justification (and, for dependencies, an
  entry in [`SECURITY.md`](SECURITY.md)).

## Security issues

**Do not open a public issue for an exploitable flaw.** Follow
[`SECURITY.md`](SECURITY.md) — use GitHub's private "Report a vulnerability".

## Development

Requirements: the .NET SDK pinned in [`global.json`](global.json) (10.0.2xx). The
net8.0/net9.0 runtimes are needed to run the full test matrix locally.

```bash
dotnet build -c Release      # warnings are errors
dotnet test  -c Release
dotnet format --verify-no-changes   # style gate (CI enforces this)
```

The post-quantum token tests need the native ML-DSA primitive (OpenSSL 3.5+ on
Linux). They **skip themselves with a reason** where it is unavailable. To run
them in a container whose system OpenSSL is older:

```bash
LD_LIBRARY_PATH=/opt/conda/lib dotnet test
```

## Pull requests

1. Branch from `main`.
2. Keep the change focused; one logical change per PR.
3. Add or update tests. A test that can't run its crypto must **skip with a
   reason** (`[SkippableFact]`), never silently pass.
4. Update `CHANGELOG.md`, and bump the version in the `.csproj` if releasing —
   the `version-sync` CI job fails if csproj / README / CHANGELOG drift apart.
5. Make sure `dotnet build`, `dotnet test`, and `dotnet format --verify-no-changes`
   are green.
6. Documentation ends with the project footer: *To God be the glory — 1
   Corinthians 10:31.*

## Code of conduct

By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).
