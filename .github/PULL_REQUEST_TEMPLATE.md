<!--
Conventional-commit title: feat: / fix: / docs: / chore: / refactor: / test: / ci:
-->

## What & why

<!-- One or two sentences. Link the issue this closes (required for anything
     beyond a genuinely trivial tweak). -->

Closes #

## Changes

<!-- Bullet the notable changes. -->

-

## Checklist

- [ ] References an issue (`Closes #N`) — or is a genuinely trivial tweak (typo/formatting)
- [ ] Ships with tests at the right tier (AGENTS.md → Code↔Tests contract)
- [ ] Updated every consumer an API change touches (`pkg/apiclient`, `web`, CLI)
- [ ] `values.schema.json` kept in sync with `values.yaml` (if Helm values changed)
- [ ] `llms.txt` + README/docs feature tables updated (if a user-visible feature changed)
- [ ] No internal references; peer projects respected (content hygiene)
- [ ] CI is green (lint, test, build)
