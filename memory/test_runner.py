"""
Memory Normalization Test Runner
Runs all normalizers against raw Volatility outputs and saves normalized JSON.
Continues processing even if individual normalizers fail.
"""

import json
import os
import sys
import traceback

from normalization.process_normalizer import ProcessNormalizer
from normalization.cmdline_normalizer import CmdlineNormalizer
from normalization.dll_normalizer import DLLNormalizer
from normalization.privilege_normalizer import PrivilegeNormalizer
from normalization.handle_normalizer import HandleNormalizer
from normalization.network_normalizer import NetworkNormalizer
from normalization.malfind_normalizer import MalfindNormalizer


def main():

    print("=" * 70)
    print("  Memory Normalization Pipeline")
    print("=" * 70)
    print()

    os.makedirs("normalized", exist_ok=True)

    normalizers = [
        (
            ProcessNormalizer(),
            "raw/pslist.txt",
            "normalized/processes.json",
        ),
        (
            CmdlineNormalizer(),
            "raw/cmdline.txt",
            "normalized/cmdline.json",
        ),
        (
            DLLNormalizer(),
            "raw/dlllist.txt",
            "normalized/dlls.json",
        ),
        (
            PrivilegeNormalizer(),
            "raw/privs.txt",
            "normalized/privileges.json",
        ),
        (
            HandleNormalizer(),
            "raw/handles.txt",
            "normalized/handles.json",
        ),
        (
            NetworkNormalizer(),
            "raw/netscan.txt",
            "normalized/network.json",
        ),
        (
            MalfindNormalizer(),
            "raw/malfind.txt",
            "normalized/malfind.json",
        ),
    ]

    success_count = 0
    fail_count = 0
    results_summary = []

    for normalizer, input_file, output_file in normalizers:

        name = normalizer.__class__.__name__
        print(f"\n{'-' * 50}")
        print(f"  {name}")
        print(f"  Input:  {input_file}")
        print(f"  Output: {output_file}")
        print(f"{'-' * 50}")

        try:

            if not os.path.exists(input_file):
                print(f"[WARN] Input file not found: {input_file} - skipping")
                results_summary.append((name, "SKIPPED", "File not found"))
                continue

            data = normalizer.normalize(input_file)

            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=4, ensure_ascii=False)

            print(f"[OK] Saved {output_file} ({len(data)} records)")
            success_count += 1
            results_summary.append((name, "OK", f"{len(data)} records"))

        except Exception as e:

            print(f"[ERROR] {name} failed on {input_file}")
            print(f"[ERROR] {type(e).__name__}: {e}")
            traceback.print_exc()
            fail_count += 1
            results_summary.append((name, "FAILED", str(e)))
            continue

    print(f"\n\n{'=' * 70}")
    print("  Summary")
    print(f"{'=' * 70}")
    print(f"  Success: {success_count}")
    print(f"  Failed:  {fail_count}")
    print(f"  Total:   {len(normalizers)}")
    print()

    for name, status, detail in results_summary:
        icon = "+" if status == "OK" else "X" if status == "FAILED" else "-"
        print(f"  {icon} {name:<25s} {status:<10s} {detail}")

    print()

    if fail_count > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()