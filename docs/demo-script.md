# Demo Script v0 (Under 5 Minutes)

1. Show case directory and no evidence in Git
- `git status --ignored`
- `ls -la cases/official/selected/`

2. Create or load case
- `./scripts/prepare_case.sh`

3. Hash evidence
- `siftguard hash cases/official/selected/<artifact>`

4. Inventory artifacts
- `siftguard inventory cases/official/selected --manifest-out runs/case_demo_001/manifest.json`

5. Parse `$MFT`, Run Keys, Amcache
- Show planned parser commands (stubs in v0).

6. Generate drop/execution/persistence timeline
- Show correlation module placeholder and planned output path.

7. Trigger one self-correction episode
- Demonstrate planned self-correction hook with a controlled mismatch.

8. Show validated findings
- Run validation over sample findings and display pass/fail.

9. Show JSONL audit ledger
- `cat runs/case_demo_001/execution_ledger.jsonl`

10. Show Markdown report
- Display generated or placeholder report path in `runs/case_demo_001/`.
