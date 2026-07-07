#!/usr/bin/env bash
# docs-xref: fail if a cross-reference doesn't resolve to a real file.
#
# Guards the stale-cross-reference class: source comments pointing at a moved
# doc, or a contract-registry row citing a file that was renamed. Two checks:
#   1. Every `docs/….md` reference in source + top-level docs resolves.
#   2. Every backtick-quoted repo file path in AGENTS.md resolves (the contract
#      registry is only useful if its file:line citations stay current).
#
# Usage: scripts/docs-xref.sh   (exits non-zero on the first broken reference)
set -euo pipefail
cd "$(dirname "$0")/.."

rc=0

# ── 1. docs/….md references in source + entry-point docs ──────────────────
doc_refs=$(
  grep -rhoE "docs/[a-zA-Z0-9_./-]+\.md" \
    --include="*.go" --include="*.py" --include="*.yaml" --include="*.yml" \
    cmd pkg services helm 2>/dev/null
  grep -rhoE "docs/[a-zA-Z0-9_./-]+\.md" AGENTS.md README.md llms.txt docs/index.md 2>/dev/null
)
while read -r ref; do
  [ -z "$ref" ] && continue
  if [ ! -f "$ref" ]; then
    echo "BROKEN docs ref: $ref"
    rc=1
  fi
done <<< "$(printf '%s\n' "$doc_refs" | sort -u)"

# ── 2. backtick-quoted repo file paths cited in AGENTS.md ──────────────────
# Only FULL repo paths (anchored on a top-level dir) — bare filenames and
# partial/relative citations are ambiguous and skipped. Strip a trailing :NN
# line number, and skip glob patterns.
agents_paths=$(
  grep -oE '`(services|pkg|cmd|helm|docs|alembic|web|proto|scripts|test)/[a-zA-Z0-9_./-]+\.(go|py|json|ya?ml|pem|ts|tsx)(:[0-9]+)?`' AGENTS.md 2>/dev/null \
    | tr -d '`' | sed -E 's/:[0-9]+$//'
)
while read -r p; do
  [ -z "$p" ] && continue
  case "$p" in *'*'*) continue;; esac  # skip globs like services/bamf/**
  if [ ! -e "$p" ]; then
    echo "BROKEN AGENTS.md path: $p"
    rc=1
  fi
done <<< "$(printf '%s\n' "$agents_paths" | sort -u)"

if [ "$rc" -eq 0 ]; then
  echo "docs-xref: all references resolve"
fi
exit "$rc"
