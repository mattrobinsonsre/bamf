#!/usr/bin/env bash
# content-hygiene: fail if any tracked file contains a forbidden internal
# identifier. Automates the AGENTS.md content-hygiene HARD gate — this is a
# public repository, so a leaked company name, internal hostname, or private
# tailnet host in source/docs is world-readable forever.
#
# Scans `git ls-files` (so gitignored files like the local CLAUDE.md are never
# looked at) and greps each text file. Runs on the CI runner where git + the
# full worktree are present.
#
# Usage: scripts/content-hygiene.sh   (exit 1 on the first offending file)
set -euo pipefail
cd "$(dirname "$0")/.."

# Forbidden internal identifiers. `[.]` keeps the dots literal.
patterns='acrolinx|markup[.]ai|markupai|acrolinx-cloud[.]net|[.]ts[.]net|grafana[.]net'

# Files where these terms are legitimately present: AGENTS.md defines the policy
# by naming them, and this script lists them as the patterns to search for.
allow='^(AGENTS\.md|scripts/content-hygiene\.sh)$'

hits=""
while IFS= read -r f; do
  case "$f" in
    "") continue ;;
  esac
  # Skip binary files (grep -I treats them as non-matching / empty).
  if grep -Iq . "$f" 2>/dev/null; then
    match=$(grep -inE "$patterns" "$f" 2>/dev/null | sed "s#^#$f:#" || true)
    [ -n "$match" ] && hits="${hits}${match}"$'\n'
  fi
done < <(git ls-files | grep -vE "$allow")

if [ -n "$hits" ]; then
  echo "content-hygiene: forbidden internal identifier(s) in tracked files:"
  printf '%s' "$hits"
  echo "Scrub the reference (anonymise the deployment) before pushing."
  exit 1
fi
echo "content-hygiene: clean"
