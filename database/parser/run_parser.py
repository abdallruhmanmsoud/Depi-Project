"""
run_parser.py
=============
Entry point. Parses all_binlogs.txt and writes database/raw/parsed_events.txt.

Usage:
    python run_parser.py [path_to_binlog_file]

Defaults to:
    database/all_binlogs.txt  (relative to project root)
"""

import os
import sys

# Allow running from the database/ directory or any parent
SCRIPT_DIR   = os.path.dirname(os.path.abspath(__file__))
DATABASE_DIR = os.path.dirname(SCRIPT_DIR)   # database/
sys.path.insert(0, SCRIPT_DIR)               # so  import mysqlbinlog_parser  works

from mysqlbinlog_parser import MysqlBinlogParser, render_events, build_summary


def main():
    # ── Resolve input path ────────────────────────────────────────────────────
    if len(sys.argv) >= 2:
        input_path = sys.argv[1]
    else:
        input_path = os.path.join(DATABASE_DIR, "all_binlogs.txt")

    output_path = os.path.join(DATABASE_DIR, "raw", "parsed_events.txt")

    print(f"[INFO] Input  : {input_path}")
    print(f"[INFO] Output : {output_path}")
    print()

    if not os.path.exists(input_path):
        print(f"[ERROR] Input file not found: {input_path}")
        sys.exit(1)

    # ── Parse ─────────────────────────────────────────────────────────────────
    parser = MysqlBinlogParser()
    try:
        events = parser.parse_file(input_path)
    except Exception as exc:
        print(f"[ERROR] Parser failed: {exc}")
        raise

    print(f"[INFO] Events extracted : {len(events)}")

    # ── Render output ─────────────────────────────────────────────────────────
    try:
        render_events(events, output_path)
    except Exception as exc:
        print(f"[ERROR] Render failed: {exc}")
        raise

    print(f"[INFO] Output written   : {output_path}")
    print()

    # ── Print summary to console ──────────────────────────────────────────────
    summary = build_summary(events)
    print("=" * 40)
    print("  Summary")
    print("=" * 40)
    for et, count in sorted(summary.items()):
        print(f"  {et:<22} : {count}")
    print(f"\n  {'TOTAL':<22} : {len(events)}")
    print()


if __name__ == "__main__":
    main()
