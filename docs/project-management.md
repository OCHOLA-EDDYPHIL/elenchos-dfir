# Project Management

## Milestones M0-M5
- M0 - Repo and environment skeleton
- M1 - Evidence inventory, hashing, audit ledger
- M2 - Artifact parsers (gated by `docs/parser-tooling-matrix.md`)
- M3 - Correlation and validation
- M4 - Agent and self-correction loop
- M5 - Submission polish

## GitHub Project columns
- Backlog
- Ready
- In Progress
- Blocked
- Review/Test
- Done

## Custom fields
- Lane: `build | research | docs | spike`
- Priority: `P0 | P1 | P2`
- Milestone: `M0 | M1 | M2 | M3 | M4 | M5`
- Estimate: `S | M | L`
- Risk: `none | scope-creep | blocker | rules-risk | evidence-risk`

## Parallelism cap
- 1 build issue
- 1 research/docs issue
- 1 AI spike issue

## First sprint backlog
- #1 Create repo skeleton and Python package layout
- #2 Add MIT license
- #3 Create GitHub Project board and labels
- #4 Add issue template and PR template
- #5 Draft concise README skeleton
- #6 Add .gitignore for evidence, VM files, secrets, run outputs
- #7 Add .env.example for OpenAI-compatible model config
- #8 Draft docs/dataset.md with official FIND EVIL sources
- #9 Implement evidence manifest schema
- #10 Implement SHA256 hashing utility
- #11 Implement JSONL execution ledger
- #12 Implement safe subprocess wrapper
- #13 Write docs/architecture.md v0
- #14 Research exact SIFT tools available for MFT, Run Keys, and Amcache parsing
- #15 Create scripts/prepare_case.sh placeholder

## Weekly checkpoint format
- Goals completed:
- Planned next week:
- Risks/blockers:
- Evidence/provenance regressions:
- Accuracy or validation notes:

## Current GitHub Project v2 status
- Intended project title: `SIFTGuard MCP Build`
- Project URL: `https://github.com/users/OCHOLA-EDDYPHIL/projects/2`
- Automated via `gh`:
- Project created (`SIFTGuard MCP Build`) and verified as open.
- Added custom single-select fields:
- `Lane`: `build | research | docs | spike`
- `Priority`: `P0 | P1 | P2`
- `Estimate`: `S | M | L`
- `Risk`: `none | scope-creep | blocker | rules-risk | evidence-risk`
- Added issues `#1` through `#15` to the project.
- Manual UI follow-up required:
- Configure the built-in `Status` field options to match workflow states:
- `Backlog | Ready | In Progress | Blocked | Review/Test | Done`
- Optional: save/filter views that align with this workflow.

## Issue closure protocol
1. Do not close an issue only because code was written.
2. Before closing, fetch the issue body and verify every acceptance criterion.
3. For every completed acceptance criterion, update `- [ ]` to `- [x]`.
4. Leave incomplete criteria unchecked.
5. If any required criterion remains unchecked, do not close the issue.
6. Add an evidence comment before closure.
7. Evidence comment must include:
   - PR link
   - commit SHA or merge SHA
   - test commands and results
   - CLI/demo output if applicable
   - SIFT validation output if applicable
   - explicit evidence-safety statement
8. PRs may close multiple issues, but only issues whose checklists are fully satisfied.
9. If a PR partially addresses an issue, use `Refs #N`, not `Closes #N`.
10. If using `Closes #N` in a PR body, update checkboxes before merge or during the final pre-merge pass.
11. After merge, verify:
   - issue is closed
   - checklist is checked
   - evidence comment exists
   - Project Status is Done
   - Project fields remain populated

Fetch issue body:
`gh issue view <N> --json body --jq .body > /tmp/issue-<N>.md`

Edit issue body:
`gh issue edit <N> --body-file /tmp/issue-<N>.md`

If `--body-file` is unsupported, use `gh api`:
`gh api -X PATCH repos/OCHOLA-EDDYPHIL/siftguard-mcp/issues/<N> -f body="$(cat /tmp/issue-<N>.md)"`

Close issue:
`gh issue close <N> --reason completed`
