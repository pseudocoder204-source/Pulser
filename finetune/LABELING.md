# Labeling instructions for finetune/batches/batch_NNN.json

Each row is `{"id": ..., "ordered_facts": [...], "skeleton": {...}}`. Fill in the
blanked `skeleton` to produce a finished report, and write the result to
`batch_NNN.labeled.json` (same shape as `batch_NNN.json`, with `skeleton` replaced
by `label`).

## The contract (same one the report LLM is held to in production)

You are a friendly, knowledgeable security diagnostician helping everyday home users
and small business owners understand the security health of their devices and
network. Your audience has NO technical background — always use plain, everyday
language.

Each finding in `ordered_facts` already has an `affected` string and a `severity`
tier computed for you — never change severity, never invent a fact not present in
`ordered_facts`.

Some findings carry a `fix_facts` object — pre-verified remediation facts (a fix
summary, ordered steps, and sometimes a `fixed_version` or `solution`) already
grounded in that finding's own data. When `fix_facts` is present, build
`how_to_fix` from it: turn its `steps` into your numbered steps, and if it has a
`fixed_version` your steps must state that version. When `fix_facts` is null,
give only safe generic advice (update the software / disable the feature /
restrict network access) and say plainly that a specific fix wasn't identified.

## What to write

- `title`, `what_it_means`, `why_it_matters`: rewrite fresh from that finding's
  `ordered_facts` fields — specific to *this* finding, not generic boilerplate.
- `how_to_fix`: numbered steps (`1. ... 2. ...`) rewritten from `fix_facts` per
  the rule above. Home-user voice: "change your router's admin password", not
  "rotate default credentials".
- Each empty `good_news` string: one reassuring sentence for that low-severity item.
- `summary`: 2-3 plain sentences on the overall situation.
- Leave `severity`, `affected`, and `references` exactly as the skeleton has them —
  those are already correct and validated mechanically.

## Hard rules (validators reject on these)

- Never write a CVE ID, a CVSS number/score, or a CPE string anywhere in the
  report. Translate everything to everyday language instead.
- **URLs go only in `references`, never inside `how_to_fix` prose** — `fix_facts`
  can carry patch URLs whose paths embed CVE IDs, and copying one into
  `how_to_fix` trips the CVE-leak check.
- Don't change `severity` or `affected` from what the skeleton already has.
- Don't add or drop findings/good_news entries — the skeleton's partition
  (critical/high/medium → findings, low → good_news) is already correct.
- Output must be valid JSON, same shape as the skeleton.

## Workflow

"label finetune/batches/batch_007.json per finetune/LABELING.md" → fill every
row's skeleton into a finished `label`, write `batch_007.labeled.json`. Spot-check
~1 in 5 batches by hand before import (read 3 random labels) — the human-voice QA
pass. Then `python3 finetune/batch_import.py finetune/batches/batch_007.labeled.json`.
