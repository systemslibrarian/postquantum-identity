#!/usr/bin/env bash
# Verifies that the package version is in sync across all the places it lives.
# Fails fast in CI if csproj / README / CHANGELOG drift apart.
#
# Sources of truth (in priority order):
#   1. <Version> in src/PostQuantum.Identity/PostQuantum.Identity.csproj
#   2. README pinned-install snippet: "dotnet add package PostQuantum.Identity --version X"
#   3. CHANGELOG.md heading: ## [X] — YYYY-MM-DD
set -euo pipefail

repo_root=$(cd "$(dirname "$0")/.." && pwd)
csproj=$repo_root/src/PostQuantum.Identity/PostQuantum.Identity.csproj
readme=$repo_root/README.md
changelog=$repo_root/CHANGELOG.md

csproj_version=$(grep -oE '<Version>[^<]+</Version>' "$csproj" | head -1 | sed -E 's|</?Version>||g')
if [[ -z $csproj_version ]]; then
  echo "::error::Could not parse <Version> from $csproj"
  exit 1
fi
echo "csproj version:    $csproj_version"

errors=0

readme_install=$(grep -oE -- '--version [0-9A-Za-z.\-]+' "$readme" | head -1 | awk '{print $2}')
if [[ -z $readme_install ]]; then
  echo "::error::README is missing a 'dotnet add package ... --version X' pinned-install line"
  errors=$((errors + 1))
elif [[ $readme_install != "$csproj_version" ]]; then
  echo "::error::README install snippet version ($readme_install) does not match csproj ($csproj_version)"
  errors=$((errors + 1))
else
  echo "README install:    $readme_install OK"
fi

# CHANGELOG must contain a heading for the current csproj version.
if ! grep -qE "^## \[$csproj_version\]" "$changelog"; then
  echo "::error::CHANGELOG.md has no '## [$csproj_version]' section"
  errors=$((errors + 1))
else
  echo "CHANGELOG entry:   $csproj_version OK"
fi

if [[ $errors -gt 0 ]]; then
  echo "::error::version-sync check failed with $errors error(s)"
  exit 1
fi

echo "All version strings are in sync at $csproj_version."
