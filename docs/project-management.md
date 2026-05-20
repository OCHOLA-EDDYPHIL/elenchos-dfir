# Project Management

## Milestones M0-M5
- M0 - Repo and environment skeleton
- M1 - Evidence inventory, hashing, audit ledger
- M2 - Artifact parsers
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
- Intended status options: `Backlog | Ready | In Progress | Blocked | Review/Test | Done`
- Intended custom fields: `Lane`, `Priority`, `Estimate`, `Risk`
- Current blocker: `gh` token missing `read:project` scope (`gh auth refresh -s read:project` required).
