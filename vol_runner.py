#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║           VOLATILITY PLUGIN RUNNER  —  Pure JSON Output                     ║
║   Runs every plugin, captures output, writes results.json  — nothing else   ║
╚══════════════════════════════════════════════════════════════════════════════╝

Usage (Vol2):
    python3 vol_runner.py -f memory.mem --vol2 vol.exe --profile Win7SP1x64
    python3 vol_runner.py -f memory.mem --vol2 vol.py  --auto-profile

Usage (Vol3):
    python3 vol_runner.py -f memory.mem --vol3 vol.py
"""

import argparse
import subprocess
import os
import sys
import json
import re
import time
import hashlib
import datetime

# ─────────────────────────────────────────────────────────────────────────────
# PLUGIN LISTS
# ─────────────────────────────────────────────────────────────────────────────

VOL2_PLUGINS = [
    "imageinfo",
    "kdbgscan",
    "pslist",
    "psscan",
    "pstree",
    "cmdline",
    "handles",
    "dlllist",
    "malfind",
    "vadinfo",
    "envars",
    "ssdt",
    "modules",
    "driverscan",
    "modscan",
    "memmap",
    "driverirp",
    "callbacks",
    "filescan",
    "hashdump",
    "privs",
    "hivelist",
    "printkey",
    "userassist",
    "cachedump",
    "svcscan",
    "netscan",
    "connections",
    "connscan",
    "timeliner",
    "yarascan",
]

# Full class-path names — work across all Vol3 versions
VOL3_PLUGINS = {
    "imageinfo":   "windows.info.Info",
    "pslist":      "windows.pslist.PsList",
    "psscan":      "windows.psscan.PsScan",
    "pstree":      "windows.pstree.PsTree",
    "cmdline":     "windows.cmdline.CmdLine",
    "handles":     "windows.handles.Handles",
    "dlllist":     "windows.dlllist.DllList",
    "malfind":     "windows.malfind.Malfind",
    "vadinfo":     "windows.vadinfo.VadInfo",
    "envars":      "windows.envars.Envars",
    "ssdt":        "windows.ssdt.SSDT",
    "modules":     "windows.modules.Modules",
    "driverscan":  "windows.driverscan.DriverScan",
    "modscan":     "windows.modscan.ModScan",
    "memmap":      "windows.memmap.Memmap",
    "driverirp":   "windows.driverirp.DriverIrp",
    "callbacks":   "windows.callbacks.Callbacks",
    "filescan":    "windows.filescan.FileScan",
    "hashdump":    "windows.hashdump.Hashdump",
    "privs":       "windows.privileges.Privs",
    "hivelist":    "windows.registry.hivelist.HiveList",
    "printkey":    "windows.registry.printkey.PrintKey",
    "userassist":  "windows.userassist.UserAssist",
    "cachedump":   "windows.cachedump.Cachedump",
    "svcscan":     "windows.svcscan.SvcScan",
    "netscan":     "windows.netscan.NetScan",
    "netstat":     "windows.netstat.NetStat",
    "yarascan":    "yarascan.YaraScan",
}

PLUGIN_DISPLAY = {
    "imageinfo":   "Image / OS Info",
    "kdbgscan":    "KDBG Scanner",
    "pslist":      "Process List",
    "psscan":      "Process Scan",
    "pstree":      "Process Tree",
    "cmdline":     "Command Lines",
    "handles":     "Open Handles",
    "dlllist":     "DLL List",
    "malfind":     "Malfind / Injection",
    "vadinfo":     "VAD Info",
    "envars":      "Environment Vars",
    "ssdt":        "SSDT Hooks",
    "modules":     "Kernel Modules",
    "driverscan":  "Driver Scan",
    "modscan":     "Module Scan",
    "memmap":      "Memory Map",
    "driverirp":   "Driver IRP",
    "callbacks":   "Kernel Callbacks",
    "filescan":    "File Object Scan",
    "hashdump":    "Password Hashes",
    "privs":       "Process Privileges",
    "hivelist":    "Registry Hives",
    "printkey":    "Registry Key Dump",
    "userassist":  "UserAssist Entries",
    "cachedump":   "Cached Credentials",
    "svcscan":     "Service Scan",
    "netscan":     "Network Scan",
    "netstat":     "Network Connections",
    "connections": "TCP Connections (XP)",
    "connscan":    "Connection Scan (XP)",
    "timeliner":   "Timeline",
    "yarascan":    "YARA Scan",
}

# ─────────────────────────────────────────────────────────────────────────────
# COLORS
# ─────────────────────────────────────────────────────────────────────────────
class C:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RESET  = "\033[0m"

# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────
def log(level, msg):
    ts  = datetime.datetime.now().strftime("%H:%M:%S")
    col = {"OK": C.GREEN, "WARN": C.YELLOW, "INFO": C.CYAN, "ERR": C.RED}.get(level, "")
    print(f"{C.DIM}{ts}{C.RESET} {col}{C.BOLD}[{level:4s}]{C.RESET} {msg}")


def sha256(path):
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return "N/A"


def build_cmd(vol_bin):
    """Prepend python interpreter if vol_bin is a .py script (fixes WinError 193)."""
    if vol_bin.lower().endswith(".py"):
        return [sys.executable, vol_bin]
    return [vol_bin]


# ─────────────────────────────────────────────────────────────────────────────
# PROFILE AUTO-DETECT  (Vol2 only)
# ─────────────────────────────────────────────────────────────────────────────
def detect_profile(vol_bin, mem_file, output_dir, timeout=120):
    log("INFO", "Auto-detecting memory profile via imageinfo …")
    out_file    = os.path.join(output_dir, "imageinfo.txt")
    stderr_file = out_file + ".stderr.tmp"
    cmd = build_cmd(vol_bin) + ["-f", mem_file, "--profile", "WinXPSP2x86", "imageinfo"]

    try:
        with open(out_file, "wb") as fout, open(stderr_file, "wb") as ferr:
            proc = subprocess.Popen(cmd, stdout=fout, stderr=ferr, stdin=subprocess.DEVNULL)
            proc.wait(timeout=timeout)

        text = open(out_file, "rb").read().decode("utf-8", errors="replace")
        m = re.search(r"Suggested Profile\(s\)\s*:\s*(.+)", text)
        if m:
            profiles = [p.strip() for p in m.group(1).split(",")]
            log("OK", f"Profile detected: {C.BOLD}{profiles[0]}{C.RESET}  "
                f"(all: {', '.join(profiles)})")
            return profiles[0], profiles
    except Exception as e:
        log("WARN", f"imageinfo failed: {e}")
    finally:
        if os.path.exists(stderr_file):
            os.remove(stderr_file)

    log("WARN", "Could not detect profile — falling back to WinXPSP2x86")
    return "WinXPSP2x86", ["WinXPSP2x86"]


# ─────────────────────────────────────────────────────────────────────────────
# CORE: RUN ONE PLUGIN  →  returns result dict
# ─────────────────────────────────────────────────────────────────────────────
def run_plugin(vol_bin, mem_file, plugin, profile, extra_args,
               output_dir, vol_version, timeout, step_num, total):

    friendly    = PLUGIN_DISPLAY.get(plugin, plugin)
    out_file    = os.path.join(output_dir, f"{plugin}.txt")
    stderr_file = out_file + ".stderr.tmp"

    # Build command
    base = build_cmd(vol_bin)
    if vol_version == 2:
        cmd = base + ["-f", mem_file, "--profile", profile, plugin] + extra_args
    else:
        plugin_path = VOL3_PLUGINS.get(plugin, plugin)
        cmd = base + ["-f", mem_file, plugin_path] + extra_args

    # Progress line
    num = f"{C.DIM}[{step_num}/{total}]{C.RESET} "
    print(f"  {C.CYAN}▶{C.RESET} {num}{C.BOLD}{friendly}{C.RESET} {C.DIM}({plugin}){C.RESET}")

    result = {
        "plugin":      plugin,
        "display":     friendly,
        "command":     " ".join(cmd),
        "status":      "ok",       # ok | warn | error | timeout | aborted
        "returncode":  None,
        "elapsed_sec": 0,
        "output_file": out_file,
        "output":      "",
        "stderr":      "",
        "error":       None,
    }

    start = time.time()
    try:
        with open(out_file, "wb") as fout, open(stderr_file, "wb") as ferr:
            proc = subprocess.Popen(cmd, stdout=fout, stderr=ferr,
                                    stdin=subprocess.DEVNULL)
            try:
                proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
                raise

        elapsed = round(time.time() - start, 2)
        result["elapsed_sec"] = elapsed
        result["returncode"]  = proc.returncode

        # Read back — safe UTF-8 decode (no cp1252 crashes)
        stdout = open(out_file,    "rb").read().decode("utf-8", errors="replace")
        stderr = open(stderr_file, "rb").read().decode("utf-8", errors="replace").strip()

        result["output"] = stdout
        result["stderr"] = stderr

        # Rewrite txt file with header + decoded content
        with open(out_file, "w", encoding="utf-8", errors="replace") as f:
            f.write(f"# plugin  : {plugin}\n")
            f.write(f"# command : {result['command']}\n")
            f.write(f"# elapsed : {elapsed}s\n")
            f.write(f"# status  : {'OK' if proc.returncode == 0 else 'WARN'}\n")
            f.write("─" * 80 + "\n\n")
            f.write(stdout)
            if stderr:
                f.write(f"\n[STDERR]\n{stderr}\n")

        # Classify result
        if proc.returncode != 0:
            result["status"] = "warn"
            # Detect common failure patterns and record them
            combined = stderr + "\n" + stdout
            if "pagemapscanner" in combined.lower() and "0.00" in combined:
                result["error"] = "missing_symbol_pack"
            elif "usage:" in combined.lower()[:200]:
                result["error"] = "plugin_not_found"
            else:
                # First meaningful error line
                for line in combined.splitlines():
                    s = line.strip()
                    if s and not s.lower().startswith(("progress:", "#", "volatility")):
                        result["error"] = s[:200]
                        break

        # Terminal status
        sym = f"{C.GREEN}✔{C.RESET}" if proc.returncode == 0 else f"{C.YELLOW}⚠{C.RESET}"
        log("OK" if proc.returncode == 0 else "WARN",
            f"{sym} {friendly} ({plugin})  [{elapsed}s]  → {out_file}")
        if result["error"]:
            print(f"       {C.YELLOW}└─ {result['error']}{C.RESET}")

    except subprocess.TimeoutExpired:
        result["status"]      = "timeout"
        result["elapsed_sec"] = round(time.time() - start, 2)
        result["error"]       = f"timeout after {timeout}s"
        log("WARN", f"⏱ {friendly} ({plugin}) timed out after {timeout}s")
        with open(out_file, "w", encoding="utf-8") as f:
            f.write(f"[TIMEOUT after {timeout}s]\n")

    except KeyboardInterrupt:
        result["status"] = "aborted"
        result["error"]  = "aborted by user"
        log("WARN", f"⏹ {friendly} ({plugin}) aborted")
        with open(out_file, "w", encoding="utf-8") as f:
            f.write("[ABORTED by user]\n")
        raise

    except Exception as e:
        result["status"]      = "error"
        result["elapsed_sec"] = round(time.time() - start, 2)
        result["error"]       = str(e)
        log("WARN", f"✘ {friendly} ({plugin}) failed: {e}")
        with open(out_file, "w", encoding="utf-8") as f:
            f.write(f"[ERROR: {e}]\n")

    finally:
        if os.path.exists(stderr_file):
            try:
                os.remove(stderr_file)
            except OSError:
                pass

    return result


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────
def parse_args():
    p = argparse.ArgumentParser(
        description="Volatility Plugin Runner — pure JSON output, no analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Volatility 2 — auto-detect profile
  python3 vol_runner.py -f memory.mem --vol2 vol.exe --auto-profile

  # Volatility 2 — known profile
  python3 vol_runner.py -f memory.mem --vol2 vol.py --profile Win7SP1x64

  # Volatility 3
  python3 vol_runner.py -f memory.mem --vol3 vol.py

  # Vol3 with YARA rules
  python3 vol_runner.py -f memory.mem --vol3 vol.py --yara-rules rules.yar

  # Skip slow plugins
  python3 vol_runner.py -f memory.mem --vol2 vol.py --profile Win7SP1x64 \\
      --skip memmap driverirp handles

  # Run only specific plugins
  python3 vol_runner.py -f memory.mem --vol3 vol.py \\
      --only pslist psscan pstree cmdline malfind netscan
"""
    )
    p.add_argument("-f", "--file",         required=True,  help="Memory image path")
    p.add_argument("--vol2",               default="",     help="Path to Volatility 2 binary")
    p.add_argument("--vol3",               default="",     help="Path to Volatility 3 vol.py")
    p.add_argument("--profile",            default="",     help="Vol2 profile (e.g. Win7SP1x64)")
    p.add_argument("--auto-profile",       action="store_true", help="Auto-detect Vol2 profile")
    p.add_argument("--output-dir", "-o",   default="",     help="Output directory")
    p.add_argument("--yara-rules",         default="",     help="YARA rules file for yarascan")
    p.add_argument("--skip",               nargs="*", default=[], help="Plugins to skip")
    p.add_argument("--only",               nargs="*", default=[], help="Run ONLY these plugins")
    p.add_argument("--timeout",            type=int, default=300, help="Per-plugin timeout (sec)")
    p.add_argument("--printkey-path",      default=r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                   help="Registry key path for printkey")
    p.add_argument("--no-output-in-json",  action="store_true",
                   help="Exclude raw plugin output from JSON (only metadata). Keeps JSON small.")
    return p.parse_args()


def main():
    print(f"""{C.CYAN}{C.BOLD}
╔══════════════════════════════════════════════════════════════════════════════╗
║           VOLATILITY PLUGIN RUNNER  —  Pure JSON Output                     ║
╚══════════════════════════════════════════════════════════════════════════════╝{C.RESET}
""")

    args = parse_args()

    # ── validate ──────────────────────────────────────────────────────────────
    if not os.path.isfile(args.file):
        log("ERR", f"Memory file not found: {args.file}")
        sys.exit(1)
    if not args.vol2 and not args.vol3:
        log("ERR", "Specify --vol2 or --vol3")
        sys.exit(1)

    vol_version = 2 if args.vol2 else 3
    vol_bin     = args.vol2 if args.vol2 else args.vol3

    # ── auto-detect Vol2/3 mismatch ───────────────────────────────────────────
    if vol_bin.lower().endswith(".py") and os.path.isfile(vol_bin):
        try:
            head = open(vol_bin, "r", encoding="utf-8", errors="replace").read(4096).lower()
            is3  = "volatility3" in head or "from volatility" in head
            is2  = "volatility.conf" in head or "addrspace" in head
            if vol_version == 3 and is2 and not is3:
                log("WARN", f"⚠  {vol_bin} looks like Vol2 but you used --vol3. "
                    f"Try --vol2 instead.")
            elif vol_version == 2 and is3 and not is2:
                log("WARN", f"⚠  {vol_bin} looks like Vol3 but you used --vol2. "
                    f"Try --vol3 instead.")
        except Exception:
            pass

    # ── output directory ──────────────────────────────────────────────────────
    if args.output_dir:
        output_dir = args.output_dir
    else:
        base = os.path.splitext(os.path.basename(args.file))[0]
        ts   = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = f"{base}_runner_{ts}"
    os.makedirs(output_dir, exist_ok=True)

    # ── hash image ────────────────────────────────────────────────────────────
    log("INFO", "Hashing image (SHA-256) …")
    image_sha = sha256(args.file)
    log("OK",   f"SHA-256: {image_sha}")

    # ── profile (Vol2) ────────────────────────────────────────────────────────
    profile          = args.profile
    detected_profiles = [profile] if profile else []
    if vol_version == 2 and (not profile or args.auto_profile):
        profile, detected_profiles = detect_profile(vol_bin, args.file,
                                                    output_dir, args.timeout)
    elif vol_version == 3:
        profile = "auto"

    log("INFO", f"Profile: {C.BOLD}{profile}{C.RESET}")

    # ── build plugin list ─────────────────────────────────────────────────────
    if args.only:
        plugins_to_run = list(args.only)
    else:
        plugins_to_run = list(VOL2_PLUGINS if vol_version == 2
                              else VOL3_PLUGINS.keys())
        if not args.yara_rules and "yarascan" in plugins_to_run:
            plugins_to_run.remove("yarascan")
        plugins_to_run = [p for p in plugins_to_run if p not in args.skip]

    total = len(plugins_to_run)
    log("INFO", f"Plugins to run: {C.BOLD}{total}{C.RESET}")
    print()
    print(f"{C.CYAN}{C.BOLD}{'─'*60}{C.RESET}")
    print(f"{C.CYAN}{C.BOLD}  PLUGIN EXECUTION  ({total} plugins){C.RESET}")
    print(f"{C.CYAN}{C.BOLD}{'─'*60}{C.RESET}\n")

    # ── run all plugins ───────────────────────────────────────────────────────
    results = {}   # plugin_name → result dict
    aborted = False

    try:
        for i, plugin in enumerate(plugins_to_run, 1):
            extra = []
            if vol_version == 2:
                if plugin == "printkey":
                    extra = ["-K", args.printkey_path]
                elif plugin == "yarascan" and args.yara_rules:
                    extra = ["--yara-file", args.yara_rules]
            else:
                if plugin == "printkey":
                    extra = ["--key", args.printkey_path]
                elif plugin == "yarascan" and args.yara_rules:
                    extra = ["--yara-file", args.yara_rules]

            r = run_plugin(vol_bin, args.file, plugin, profile,
                           extra, output_dir, vol_version,
                           args.timeout, i, total)
            results[plugin] = r

    except KeyboardInterrupt:
        aborted = True
        done    = len(results)
        skipped = plugins_to_run[done:]
        print()
        log("WARN", f"⏹  Interrupted — {done} done, {len(skipped)} skipped")
        if skipped:
            print(f"  {C.DIM}Skipped: {', '.join(skipped[:8])}"
                  f"{'…' if len(skipped) > 8 else ''}{C.RESET}")
        print(f"  {C.DIM}Saving partial JSON from completed plugins…{C.RESET}\n")

    # ── status summary bar ────────────────────────────────────────────────────
    ok_n   = sum(1 for r in results.values() if r["status"] == "ok")
    warn_n = sum(1 for r in results.values() if r["status"] == "warn")
    err_n  = sum(1 for r in results.values()
                 if r["status"] in ("error", "timeout", "aborted"))
    print()
    print(f"  {C.CYAN}Results:{C.RESET}  "
          f"{C.GREEN}✔ {ok_n} OK{C.RESET}  "
          f"{C.YELLOW}⚠ {warn_n} warned{C.RESET}  "
          f"{C.RED}✘ {err_n} errors{C.RESET}  "
          f"{'(partial — interrupted)' if aborted else ''}")

    # Detect 100% PageMapScanner failure
    pms_hits = sum(1 for r in results.values()
                   if r.get("error") == "missing_symbol_pack")
    if pms_hits >= 3:
        print()
        print(f"  {C.YELLOW}{C.BOLD}ROOT CAUSE: Missing Vol3 symbol pack{C.RESET}")
        print(f"  {C.DIM}  1. python3 {vol_bin} -f {args.file} banners.Banners{C.RESET}")
        print(f"  {C.DIM}  2. Download windows.zip → volatility3/symbols/{C.RESET}")
        print(f"  {C.DIM}     git clone https://github.com/JPCERTCC/Windows-Symbol-Tables{C.RESET}")

    # ── build JSON ────────────────────────────────────────────────────────────
    print()
    log("INFO", "Building JSON …")

    # Metadata block
    meta = {
        "image_file":         os.path.abspath(args.file),
        "sha256":             image_sha,
        "volatility_version": vol_version,
        "volatility_binary":  vol_bin,
        "profile":            profile,
        "detected_profiles":  detected_profiles,
        "analysis_date":      datetime.datetime.now().isoformat(),
        "plugins_requested":  total,
        "plugins_completed":  len(results),
        "plugins_ok":         ok_n,
        "plugins_warned":     warn_n,
        "plugins_errored":    err_n,
        "aborted":            aborted,
        "output_dir":         os.path.abspath(output_dir),
    }

    # Per-plugin results
    plugins_out = {}
    for name, r in results.items():
        entry = {
            "display":     r["display"],
            "command":     r["command"],
            "status":      r["status"],
            "returncode":  r["returncode"],
            "elapsed_sec": r["elapsed_sec"],
            "output_file": r["output_file"],
            "error":       r["error"],
        }
        # Include raw output unless user opted out
        if not args.no_output_in_json:
            entry["output"] = r["output"]
            entry["stderr"] = r["stderr"]
        plugins_out[name] = entry

    output_json = {
        "meta":    meta,
        "plugins": plugins_out,
    }

    # ── write JSON ────────────────────────────────────────────────────────────
    json_path = os.path.join(output_dir, "results.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(output_json, f, indent=2, ensure_ascii=False)

    log("OK", f"JSON saved → {C.BOLD}{json_path}{C.RESET}")

    # ── final summary ─────────────────────────────────────────────────────────
    print()
    print(f"{C.CYAN}{'═'*70}{C.RESET}")
    print(f"{C.BOLD}  DONE{C.RESET}")
    print(f"{'═'*70}")
    print(f"  Image        : {args.file}")
    print(f"  SHA-256      : {image_sha}")
    print(f"  Profile      : {profile}")
    print(f"  Plugins run  : {len(results)} / {total}")
    print(f"  {C.GREEN}✔ OK{C.RESET}       : {ok_n}")
    print(f"  {C.YELLOW}⚠ Warned{C.RESET}   : {warn_n}")
    print(f"  {C.RED}✘ Errors{C.RESET}   : {err_n}")
    print(f"  Output dir   : {os.path.abspath(output_dir)}")
    print(f"  JSON         : {json_path}")
    print(f"{'═'*70}\n")


if __name__ == "__main__":
    main()
