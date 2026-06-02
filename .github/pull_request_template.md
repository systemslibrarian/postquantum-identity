<!-- Thanks for contributing! Please read CONTRIBUTING.md first. -->

## What & why

<!-- What does this change and why? Link any related issue. -->

## Checklist

- [ ] One focused, logical change
- [ ] `dotnet build -c Release` is clean (warnings are errors)
- [ ] `dotnet test -c Release` passes (PQ tests skip-with-reason where ML-DSA is unavailable)
- [ ] `dotnet format --verify-no-changes` is clean
- [ ] Tests added/updated (and any crypto test that can't run **skips with a reason**)
- [ ] `CHANGELOG.md` updated (and version bumped in the `.csproj` if releasing)
- [ ] Docs updated where behavior or the public surface changed
- [ ] No new public API or dependency without justification (and a `SECURITY.md` note for deps)
- [ ] Fail-closed behavior preserved (no `alg: none`, no silent downgrade, malformed input never verifies)

## Security impact

<!-- Does this touch hashing, token issuance/validation, or key handling?
     If unsure, say so. Do NOT use a PR to disclose an exploitable flaw — see SECURITY.md. -->
