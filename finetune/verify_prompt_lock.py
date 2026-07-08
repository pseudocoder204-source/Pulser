"""Fail loudly if agent._REPORT_SYSTEM_PROMPT has drifted from the locked snapshot.

FinetuneGuide.txt Step 1: every training example must be collected against the
byte-identical system prompt used at inference, or the LoRA overfits to a prompt
that later changes. Run this before/during any data-collection session:

    python3 finetune/verify_prompt_lock.py
"""
import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

LOCK_FILE = Path(__file__).parent / "report_prompt.lock.txt"
LOCKED_SHA256 = "b3cc137fa2932f72b3741f91035590caab08cbfa978b0e1ac31479a1c2032911"


def main() -> int:
    import agent

    live = agent._REPORT_SYSTEM_PROMPT
    live_hash = hashlib.sha256(live.encode()).hexdigest()
    locked = LOCK_FILE.read_text()
    locked_hash = hashlib.sha256(locked.encode()).hexdigest()

    if locked_hash != LOCKED_SHA256:
        print(f"[FAIL] {LOCK_FILE} itself has been edited — it no longer matches "
              f"the recorded lock hash. Re-lock intentionally or restore it.", file=sys.stderr)
        return 1

    if live_hash != LOCKED_SHA256:
        print("[FAIL] agent._REPORT_SYSTEM_PROMPT no longer matches the locked "
              f"snapshot at {LOCK_FILE}.\n"
              f"  locked sha256: {LOCKED_SHA256}\n"
              f"  live   sha256: {live_hash}\n"
              "If this change is intentional, finish/discard the current data "
              "collection run first, then re-run this script with --relock.",
              file=sys.stderr)
        if "--relock" in sys.argv:
            LOCK_FILE.write_text(live)
            print(f"[RELOCK] wrote new snapshot and hash {live_hash} — update "
                  "LOCKED_SHA256 in this script.", file=sys.stderr)
        return 1

    print(f"[OK] _REPORT_SYSTEM_PROMPT matches the locked snapshot ({LOCKED_SHA256[:12]}...).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
