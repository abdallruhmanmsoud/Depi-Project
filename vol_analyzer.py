#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║          VOLATILITY MEMORY FORENSICS AUTOMATION & ANALYSIS TOOL             ║
║                     Full-Spectrum Investigation Script                       ║
╚══════════════════════════════════════════════════════════════════════════════╝

Author  : Memory Forensics Automation Framework
Supports: Volatility 2 & Volatility 3
Output  : Per-plugin text files + unified HTML/JSON forensics report
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
from pathlib import Path
from collections import defaultdict


# ─────────────────────────────────────────────────────────────────────────────
# MITRE ATT&CK MAPPING
# ─────────────────────────────────────────────────────────────────────────────
MITRE_MAP = {
    "process_injection":     ("T1055",  "Process Injection",                    "Defense Evasion / Privilege Escalation"),
    "registry_run":          ("T1547",  "Boot/Logon Autostart via Registry Run", "Persistence"),
    "credential_dump":       ("T1003",  "OS Credential Dumping",                "Credential Access"),
    "hidden_process":        ("T1564",  "Hide Artifacts",                        "Defense Evasion"),
    "kernel_hook":           ("T1014",  "Rootkit",                              "Defense Evasion"),
    "network_c2":            ("T1071",  "Application Layer Protocol (C2)",      "Command and Control"),
    "dll_injection":         ("T1055.001", "DLL Injection",                     "Defense Evasion"),
    "reflective_dll":        ("T1055.002", "Portable Executable Injection",     "Defense Evasion"),
    "service_persistence":   ("T1543.003", "Windows Service",                   "Persistence"),
    "scheduled_task":        ("T1053",  "Scheduled Task/Job",                   "Execution / Persistence"),
    "lsass_access":          ("T1003.001", "LSASS Memory",                      "Credential Access"),
    "rwx_memory":            ("T1055",  "RWX Memory Injection",                 "Defense Evasion"),
    "unusual_parent":        ("T1134",  "Access Token Manipulation",            "Defense Evasion"),
    "env_manipulation":      ("T1574",  "Hijack Execution Flow",                "Persistence"),
    "driver_load":           ("T1215",  "Kernel Modules and Extensions",        "Persistence"),
    "userassist":            ("T1204",  "User Execution",                       "Execution"),
    "hashdump":              ("T1003",  "Credential Dumping via SAM",           "Credential Access"),
}

# ─────────────────────────────────────────────────────────────────────────────
# KNOWN SUSPICIOUS INDICATORS
# ─────────────────────────────────────────────────────────────────────────────
SUSPICIOUS_PROCESS_NAMES = [
    "mimikatz", "pwdump", "wce.exe", "fgdump", "gsecdump",
    "procdump", "meterpreter", "beacon", "cobaltstrike",
    "empire", "powersploit", "metasploit", "netcat", "nc.exe",
    "psexec", "wmiexec", "dcomexec", "atexec", "smbexec",
    "secretsdump", "lsadump", "wdigest", "kerberoast",
    "sharphound", "bloodhound", "rubeus", "kerbrute",
]

SUSPICIOUS_PATHS = [
    r"\\temp\\", r"\\tmp\\", r"\\appdata\\local\\temp\\",
    r"\\users\\public\\", r"\\programdata\\",
    r"\\windows\\temp\\", r"\\recycle", r"\\$recycle",
]

LEGIT_PROCESS_PARENTS = {
    "services.exe":    ["wininit.exe"],
    "svchost.exe":     ["services.exe"],
    "lsass.exe":       ["wininit.exe"],
    "smss.exe":        ["system"],
    "csrss.exe":       ["smss.exe"],
    "wininit.exe":     ["smss.exe"],
    "winlogon.exe":    ["smss.exe"],
    "explorer.exe":    ["userinit.exe", "winlogon.exe"],
    "taskhost.exe":    ["services.exe"],
    "taskhostw.exe":   ["services.exe"],
    "spoolsv.exe":     ["services.exe"],
    "iexplore.exe":    ["explorer.exe"],
    "chrome.exe":      ["explorer.exe"],
}

SENSITIVE_PROCESSES = ["lsass.exe", "winlogon.exe", "csrss.exe", "smss.exe", "wininit.exe"]

# ─────────────────────────────────────────────────────────────────────────────
# VOLATILITY 2 PLUGIN LIST
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
    "sockets",
    "sockscan",
    "timeliner",
    "yarascan",        # only if --yara-rules provided
]

# ─────────────────────────────────────────────────────────────────────────────
# PLUGIN DISPLAY NAMES  (plugin_key → "Friendly Name")
# ─────────────────────────────────────────────────────────────────────────────
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
    "connections": "TCP Connections",
    "connscan":    "Connection Scan",
    "sockets":     "Open Sockets",
    "sockscan":    "Socket Scan",
    "timeliner":   "Timeline",
    "yarascan":    "YARA Scan",
}

# ─────────────────────────────────────────────────────────────────────────────
# VOLATILITY 3 PLUGIN MAPPING
# Full dotted class paths work across all Vol3 versions (1.x and 2.x).
# Short names like "windows.netscan" fail in some builds → always use full path.
# ─────────────────────────────────────────────────────────────────────────────
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

# ─────────────────────────────────────────────────────────────────────────────
# COLORS  (ANSI terminal)
# ─────────────────────────────────────────────────────────────────────────────
class C:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    CYAN   = "\033[96m"
    WHITE  = "\033[97m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RESET  = "\033[0m"

def banner():
    print(f"""{C.CYAN}{C.BOLD}
╔══════════════════════════════════════════════════════════════════════════════╗
║       VOLATILITY MEMORY FORENSICS AUTOMATION & ANALYSIS TOOL v2.0           ║
║                  Full-Spectrum Memory Investigation                          ║
╚══════════════════════════════════════════════════════════════════════════════╝{C.RESET}
""")

def log(level, msg):
    ts = datetime.datetime.now().strftime("%H:%M:%S")
    colors = {"INFO": C.BLUE, "OK": C.GREEN, "WARN": C.YELLOW,
              "CRIT": C.RED,  "STEP": C.CYAN, "DIM": C.DIM}
    col = colors.get(level, C.WHITE)
    label = f"[{level:4s}]"
    print(f"{C.DIM}{ts}{C.RESET} {col}{C.BOLD}{label}{C.RESET} {msg}")


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────
def sha256(path: str) -> str:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return "N/A"


def _build_cmd(vol_bin: str) -> list:
    """
    If vol_bin is a .py script, prepend the current Python interpreter so it
    runs correctly on all platforms (fixes WinError 193 on Windows).
    """
    if vol_bin.lower().endswith(".py"):
        return [sys.executable, vol_bin]
    return [vol_bin]


def run_plugin(vol_bin: str, mem_file: str, plugin: str,
               profile: str, extra_args: list, output_dir: str,
               vol_version: int, timeout: int = 300,
               step_num: int = 0, total: int = 0) -> dict:
    """
    Run a single Volatility plugin, save output to file, return result dict.
    """
    out_file = os.path.join(output_dir, f"{plugin}.txt")
    base_cmd = _build_cmd(vol_bin)

    if vol_version == 2:
        cmd = base_cmd + ["-f", mem_file, "--profile", profile, plugin] + extra_args
    else:  # vol3
        mapped = VOL3_PLUGINS.get(plugin, plugin)
        cmd = base_cmd + ["-f", mem_file, mapped] + extra_args

    # ── pretty numbered display ───────────────────────────────────────────────
    friendly = PLUGIN_DISPLAY.get(plugin, plugin)
    num_tag  = f"{C.DIM}[{step_num}/{total}]{C.RESET} " if step_num else ""
    print(f"  {C.CYAN}▶{C.RESET} {num_tag}{C.BOLD}{friendly}{C.RESET} "
          f"{C.DIM}({plugin}){C.RESET}")
    start = time.time()
    result = {"plugin": plugin, "cmd": " ".join(cmd),
              "output_file": out_file, "status": "ok",
              "elapsed": 0, "output": ""}

    # Use a temp file for stderr so we never buffer large output in RAM.
    # This avoids the Windows Python 3.14 pipe-deadlock bug where
    # capture_output=True hangs when Vol3 produces large stdout.
    stderr_file = out_file + ".stderr.tmp"

    try:
        with open(out_file, "wb") as fout, open(stderr_file, "wb") as ferr:
            proc = subprocess.Popen(
                cmd,
                stdout=fout,
                stderr=ferr,
                stdin=subprocess.DEVNULL,
            )
            try:
                proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
                raise

        elapsed = round(time.time() - start, 2)
        result["elapsed"] = elapsed

        # Read back from files — safe decode, no pipe buffer limits
        with open(out_file, "rb") as f:
            raw_stdout = f.read()
        with open(stderr_file, "rb") as f:
            raw_stderr = f.read()

        stdout = raw_stdout.decode("utf-8", errors="replace")
        stderr = raw_stderr.decode("utf-8", errors="replace").strip()
        output = stdout + (f"\n[STDERR]\n{stderr}" if stderr else "")
        result["output"] = output

        # Rewrite the output file with the header + decoded content
        with open(out_file, "w", encoding="utf-8", errors="replace") as f:
            f.write(f"# Plugin  : {plugin}\n")
            f.write(f"# Command : {result['cmd']}\n")
            f.write(f"# Time    : {datetime.datetime.now().isoformat()}\n")
            f.write(f"# Elapsed : {elapsed}s\n")
            f.write("─" * 80 + "\n\n")
            f.write(output)

        status_col = C.GREEN if proc.returncode == 0 else C.YELLOW
        status_sym = "✔" if proc.returncode == 0 else "⚠"
        log("OK", f"{status_col}{status_sym} {friendly} ({plugin}){C.RESET}  [{elapsed}s]  → {out_file}")

        # ── If non-zero exit, print the first meaningful error line ──────────
        if proc.returncode != 0:
            result["status"] = "warn"
            result["returncode"] = proc.returncode
            combined = stderr + "\n" + stdout
            SKIP_PREFIXES = ("progress:", "volatility", "scanning filelayer",
                             "#", "offset", "pid", "name")
            hint = ""
            for line in combined.splitlines():
                stripped = line.strip()
                low = stripped.lower()
                if not stripped:
                    continue
                if any(low.startswith(p) for p in SKIP_PREFIXES):
                    continue
                hint = stripped[:140]
                break

            if "pagemapscanner" in combined.lower() and "0.00" in combined:
                print(f"       {C.YELLOW}└─ ⚠ Vol3 found image but NO kernel structures — missing symbol pack{C.RESET}")
            elif "usage:" in combined.lower()[:200]:
                print(f"       {C.YELLOW}└─ ✘ Plugin name not recognised by this Vol3 build{C.RESET}")
            elif hint:
                print(f"       {C.YELLOW}└─ {hint}{C.RESET}")
        else:
            result["returncode"] = 0

    except subprocess.TimeoutExpired:
        result["status"] = "timeout"
        result["output"] = f"[TIMEOUT after {timeout}s]"
        log("WARN", f"⏱ {friendly} ({plugin}) timed out after {timeout}s")
        with open(out_file, "w", encoding="utf-8") as f:
            f.write(f"[TIMEOUT after {timeout}s]\n")
    except KeyboardInterrupt:
        result["status"] = "aborted"
        result["output"] = "[ABORTED by user]"
        log("WARN", f"⏹ {friendly} ({plugin}) aborted by user (Ctrl+C)")
        with open(out_file, "w", encoding="utf-8") as f:
            f.write("[ABORTED by user]\n")
        raise   # re-raise so main() can catch it and print the summary cleanly
    except Exception as e:
        result["status"] = "error"
        result["output"] = str(e)
        log("WARN", f"✘ {friendly} ({plugin}) failed: {e}")
        with open(out_file, "w", encoding="utf-8") as f:
            f.write(f"[ERROR: {e}]\n")
    finally:
        # Always clean up the temp stderr file
        try:
            if os.path.exists(stderr_file):
                os.remove(stderr_file)
        except OSError:
            pass

    return result


# ─────────────────────────────────────────────────────────────────────────────
# PROFILE DETECTION
# ─────────────────────────────────────────────────────────────────────────────
def detect_profile(vol_bin: str, mem_file: str, vol_version: int,
                   output_dir: str, timeout: int = 120) -> str:
    log("STEP", "Detecting memory profile / OS info …")

    if vol_version == 2:
        r = run_plugin(vol_bin, mem_file, "imageinfo", "WinXPSP2x86",
                       [], output_dir, vol_version, timeout)
        text = r["output"]
        m = re.search(r"Suggested Profile\(s\)\s*:\s*(.+)", text)
        if m:
            profiles = [p.strip() for p in m.group(1).split(",")]
            chosen = profiles[0]
            log("OK", f"Auto-detected profile: {C.BOLD}{chosen}{C.RESET}")
            log("INFO", f"All suggestions: {', '.join(profiles)}")
            return chosen
    else:
        r = run_plugin(vol_bin, mem_file, "imageinfo", "", [], output_dir, vol_version, timeout)
        log("OK", "Vol3 info gathered (profile auto-detected by Vol3)")
        return "auto"

    log("WARN", "Could not auto-detect profile. Using WinXPSP2x86 as fallback.")
    return "WinXPSP2x86"


# ─────────────────────────────────────────────────────────────────────────────
# ANALYSIS ENGINE
# ─────────────────────────────────────────────────────────────────────────────
class AnalysisEngine:
    def __init__(self, results: dict, output_dir: str):
        self.results = results      # {plugin: result_dict}  ← also used by ReportGenerator
        self.output_dir = output_dir
        self.findings = []          # list of finding dicts
        self.mitre_hits = []
        self.timeline = []
        self.process_table = {}     # pid → {name, ppid, ...}
        self.network_table = []

    # ── helpers ───────────────────────────────────────────────────────────────
    def _output(self, plugin: str) -> str:
        r = self.results.get(plugin, {})
        if r.get("status") in ("error", "timeout"):
            return ""
        text = r.get("output", "")
        if not text:
            return ""
        # Always reject obvious error/noise markers
        if text.startswith("[ERROR") or text.startswith("[TIMEOUT"):
            return ""
        # For warned plugins, check if the output is real data or just noise
        if r.get("status") == "warn":
            meaningful_lines = 0
            NOISE = ("progress:", "usage:", "volatility", "scanning filelayer",
                     "[stderr]", "traceback", "error:", "warning:")
            for line in text.splitlines():
                low = line.strip().lower()
                if not low:
                    continue
                if not any(low.startswith(n) for n in NOISE):
                    meaningful_lines += 1
            # Require at least 2 non-noise lines to be considered real output
            if meaningful_lines < 2:
                return ""
        return text

    def _add_finding(self, severity: str, category: str, title: str,
                     detail: str, mitre_key: str = None, evidence: str = ""):
        f = {
            "severity":  severity,   # CRITICAL / HIGH / MEDIUM / LOW / INFO
            "category":  category,
            "title":     title,
            "detail":    detail,
            "evidence":  evidence[:2000],
        }
        if mitre_key and mitre_key in MITRE_MAP:
            tid, tname, tactic = MITRE_MAP[mitre_key]
            f["mitre_id"]     = tid
            f["mitre_name"]   = tname
            f["mitre_tactic"] = tactic
            self.mitre_hits.append({"id": tid, "name": tname, "tactic": tactic})
        self.findings.append(f)
        col = {"CRITICAL": C.RED, "HIGH": C.RED, "MEDIUM": C.YELLOW,
               "LOW": C.BLUE, "INFO": C.DIM}.get(severity, C.WHITE)
        log(severity[:4], f"{col}[{category}]{C.RESET} {title}")

    def _add_timeline(self, ts: str, plugin: str, event: str):
        self.timeline.append({"ts": ts, "plugin": plugin, "event": event})

    # ── parse helpers ─────────────────────────────────────────────────────────
    def _parse_pslist(self):
        text = self._output("pslist")
        procs = {}
        for line in text.splitlines():
            # Vol2: Offset(V)  Name  PID  PPID  Thds  Hnds  Sess  Wow64  Start  Exit
            m = re.match(
                r"(?:0x\S+)\s+([\w\.\-]+)\s+(\d+)\s+(\d+)\s+\d+\s+\d+\s+\S+\s+\S+\s+(\S+\s+\S+)?",
                line
            )
            if m:
                name, pid, ppid, start = m.group(1), int(m.group(2)), int(m.group(3)), m.group(4) or ""
                procs[pid] = {"name": name, "ppid": ppid, "start": start.strip()}
        return procs

    def _parse_psscan(self):
        text = self._output("psscan")
        procs = {}
        for line in text.splitlines():
            m = re.match(r"(?:0x\S+)\s+([\w\.\-]+)\s+(\d+)\s+(\d+)", line)
            if m:
                name, pid, ppid = m.group(1), int(m.group(2)), int(m.group(3))
                procs[pid] = {"name": name, "ppid": ppid}
        return procs

    # ── analysis steps ────────────────────────────────────────────────────────

    def analyze_processes(self):
        log("STEP", "Analyzing process list …")
        pslist_procs = self._parse_pslist()
        psscan_procs = self._parse_psscan()
        self.process_table = pslist_procs

        if not pslist_procs:
            self._add_finding("INFO", "PROCESS", "pslist output empty or unparsed",
                              "Check raw pslist output manually.")
            return

        # duplicate names
        name_count = defaultdict(list)
        for pid, p in pslist_procs.items():
            name_count[p["name"].lower()].append(pid)

        for name, pids in name_count.items():
            if len(pids) > 1:
                parents = {pslist_procs[pid]["ppid"] for pid in pids}
                # multiple svchost ok, but multiple lsass / csrss etc. is suspicious
                if name in ["lsass.exe", "csrss.exe", "smss.exe", "wininit.exe"]:
                    self._add_finding(
                        "CRITICAL", "PROCESS", f"Multiple instances of {name}",
                        f"PIDs: {pids} — normally only 1 instance should run.",
                        "hidden_process",
                        evidence=f"{name} PIDs={pids}"
                    )
                elif len(parents) > 1:
                    self._add_finding(
                        "HIGH", "PROCESS", f"Multiple {name} with different parents",
                        f"PIDs={pids} parents={list(parents)}",
                        "unusual_parent"
                    )

        # unusual parents
        for pid, p in pslist_procs.items():
            name_low = p["name"].lower()
            ppid = p["ppid"]
            if name_low in LEGIT_PROCESS_PARENTS:
                legit = LEGIT_PROCESS_PARENTS[name_low]
                parent_name = pslist_procs.get(ppid, {}).get("name", "").lower()
                if parent_name and parent_name not in legit and ppid != 0:
                    self._add_finding(
                        "HIGH", "PROCESS",
                        f"Unusual parent for {p['name']}",
                        f"PID={pid} has parent {parent_name} (PID={ppid}). "
                        f"Expected: {legit}",
                        "unusual_parent",
                        evidence=f"{p['name']} → parent={parent_name}"
                    )

        # suspicious names
        for pid, p in pslist_procs.items():
            name_low = p["name"].lower()
            for sus in SUSPICIOUS_PROCESS_NAMES:
                if sus in name_low:
                    self._add_finding(
                        "CRITICAL", "PROCESS",
                        f"Suspicious process name: {p['name']}",
                        f"PID={pid}. Matches known attack tool pattern '{sus}'.",
                        "process_injection",
                        evidence=f"{p['name']} PID={pid}"
                    )

        # pslist vs psscan discrepancies  → hidden processes
        pslist_pids = set(pslist_procs.keys())
        psscan_pids = set(psscan_procs.keys())

        hidden = psscan_pids - pslist_pids
        if hidden:
            names = [psscan_procs[p]["name"] for p in hidden]
            self._add_finding(
                "CRITICAL", "PROCESS",
                f"Hidden processes detected ({len(hidden)})",
                f"Found in psscan but NOT in pslist → likely rootkit / terminated.\n"
                f"PIDs: {list(hidden)}\nNames: {names}",
                "hidden_process",
                evidence=str({p: psscan_procs[p] for p in hidden})
            )

        self._add_finding("INFO", "PROCESS",
                          f"Total pslist={len(pslist_procs)} psscan={len(psscan_procs)}",
                          "Process enumeration complete.")

    def analyze_malfind(self):
        log("STEP", "Analyzing malfind (code injection / RWX regions) …")
        text = self._output("malfind")
        if not text.strip() or "[ERROR" in text:
            return

        # count injection hits
        procs_with_inject = set()
        rwx_count = 0
        mz_count = 0

        for line in text.splitlines():
            m = re.match(r"Process:\s*([\w\.\-]+)\s+Pid:\s*(\d+)", line)
            if m:
                procs_with_inject.add((m.group(1), m.group(2)))
            if "PAGE_EXECUTE_READWRITE" in line or "RWX" in line:
                rwx_count += 1
            if "4d 5a" in line.lower() or "MZ" in line:
                mz_count += 1

        if procs_with_inject:
            detail = (f"{len(procs_with_inject)} process(es) with suspicious memory regions.\n"
                      f"RWX pages: {rwx_count}, MZ headers in memory: {mz_count}\n"
                      f"Processes: {[p[0] for p in procs_with_inject]}")
            sev = "CRITICAL" if mz_count > 0 else "HIGH"
            self._add_finding(sev, "INJECTION",
                              f"Code injection detected ({len(procs_with_inject)} procs)",
                              detail, "process_injection",
                              evidence=text[:1000])

            if mz_count > 0:
                self._add_finding("CRITICAL", "INJECTION",
                                  "PE (MZ) headers found in injected memory",
                                  "Strongly indicates reflective DLL / shellcode injection.",
                                  "reflective_dll")

        # check lsass specifically
        lsass_inject = [p for p in procs_with_inject if "lsass" in p[0].lower()]
        if lsass_inject:
            self._add_finding("CRITICAL", "CREDENTIAL",
                              "Injection detected in lsass.exe — potential Mimikatz/credential dump",
                              f"lsass entries: {lsass_inject}",
                              "lsass_access")

    def analyze_network(self):
        log("STEP", "Analyzing network connections …")
        netscan_text = self._output("netscan") or self._output("connections") or ""
        if not netscan_text.strip():
            return

        connections = []
        suspicious_ports = {4444, 1337, 31337, 8080, 9090, 6666, 6667, 6660, 6661, 8888, 2222}

        for line in netscan_text.splitlines():
            # parse: Proto  LocalAddr:Port  ForeignAddr:Port  State  PID  Owner
            m = re.search(
                r"(TCP|UDP)\s+([\d\.]+):(\d+)\s+([\d\.]+):(\d+)\s+(\w+)?\s+(\d+)\s*([\w\.\-]*)",
                line, re.IGNORECASE
            )
            if m:
                proto = m.group(1)
                local_ip, local_port = m.group(2), int(m.group(3))
                remote_ip, remote_port = m.group(4), int(m.group(5))
                state = m.group(6) or ""
                pid = m.group(7)
                owner = m.group(8) or ""
                conn = {
                    "proto": proto, "local_ip": local_ip, "local_port": local_port,
                    "remote_ip": remote_ip, "remote_port": remote_port,
                    "state": state, "pid": pid, "owner": owner
                }
                connections.append(conn)

                # flag suspicious
                if remote_port in suspicious_ports or local_port in suspicious_ports:
                    self._add_finding(
                        "HIGH", "NETWORK",
                        f"Suspicious port {remote_port or local_port} in connection",
                        f"{proto} {local_ip}:{local_port} → {remote_ip}:{remote_port} "
                        f"State={state} PID={pid} Owner={owner}",
                        "network_c2",
                        evidence=line
                    )
                # external connections from sensitive processes
                if owner.lower() in SENSITIVE_PROCESSES:
                    if not remote_ip.startswith("127.") and remote_ip not in ("0.0.0.0", "", "*"):
                        self._add_finding(
                            "CRITICAL", "NETWORK",
                            f"Sensitive process {owner} has external network connection",
                            f"{proto} {local_ip}:{local_port} → {remote_ip}:{remote_port}",
                            "network_c2",
                            evidence=line
                        )

        self.network_table = connections
        self._add_finding("INFO", "NETWORK",
                          f"Total connections parsed: {len(connections)}",
                          "Network connection analysis complete.")

    def analyze_ssdt(self):
        log("STEP", "Analyzing SSDT hooks …")
        text = self._output("ssdt")
        if not text.strip():
            return
        hooked = []
        for line in text.splitlines():
            # hooked entries show module other than ntoskrnl / win32k
            m = re.search(r"\[(\d+)\]\s+(\S+)\s+\((.+)\)", line)
            if m:
                idx, addr, module = m.group(1), m.group(2), m.group(3)
                mod_low = module.lower()
                if "ntoskrnl" not in mod_low and "win32k" not in mod_low and "ntkrnl" not in mod_low:
                    hooked.append(f"Entry {idx}: {addr} → {module}")

        if hooked:
            self._add_finding(
                "CRITICAL", "ROOTKIT",
                f"SSDT hooks detected ({len(hooked)} entries)",
                "Kernel-level hooks indicate rootkit activity.\n" + "\n".join(hooked[:20]),
                "kernel_hook",
                evidence="\n".join(hooked[:30])
            )

    def analyze_modules(self):
        log("STEP", "Analyzing kernel modules/drivers …")
        mod_text  = self._output("modules")
        scan_text = self._output("modscan")

        if not mod_text.strip():
            return

        # parse module names from modules
        mod_names = set()
        for line in mod_text.splitlines():
            m = re.search(r"\\(?:SystemRoot|Windows)\\[^\s]+\.sys", line, re.IGNORECASE)
            if m:
                mod_names.add(m.group(0).lower())

        # scan names not in active list → hidden drivers
        scan_names = set()
        if scan_text:
            for line in scan_text.splitlines():
                m = re.search(r"\\(?:SystemRoot|Windows)\\[^\s]+\.sys", line, re.IGNORECASE)
                if m:
                    scan_names.add(m.group(0).lower())

        hidden_drivers = scan_names - mod_names
        if hidden_drivers:
            self._add_finding(
                "CRITICAL", "ROOTKIT",
                f"Hidden kernel drivers detected ({len(hidden_drivers)})",
                "Found in modscan but NOT in active modules list:\n" +
                "\n".join(list(hidden_drivers)[:20]),
                "driver_load",
                evidence=str(hidden_drivers)[:1000]
            )

        # suspicious driver paths (not in system32/drivers)
        suspicious_drivers = []
        for line in mod_text.splitlines():
            if ".sys" in line.lower():
                for sus_path in SUSPICIOUS_PATHS:
                    if sus_path in line.lower():
                        suspicious_drivers.append(line.strip())
        if suspicious_drivers:
            self._add_finding(
                "HIGH", "ROOTKIT",
                f"Drivers loaded from suspicious paths ({len(suspicious_drivers)})",
                "\n".join(suspicious_drivers[:10]),
                "driver_load",
                evidence="\n".join(suspicious_drivers[:10])
            )

    def analyze_registry(self):
        log("STEP", "Analyzing registry persistence …")
        hivelist_text = self._output("hivelist")
        printkey_text = self._output("printkey")

        run_keys = []
        run_key_patterns = [
            r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
            r"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
            r"SYSTEM\\CurrentControlSet\\Services",
        ]

        for line in printkey_text.splitlines():
            for pat in run_key_patterns:
                if re.search(pat, line, re.IGNORECASE):
                    run_keys.append(line.strip())

        # also look for any REG_SZ values in Run keys
        in_run_section = False
        for line in printkey_text.splitlines():
            if "\\Run" in line or "\\RunOnce" in line:
                in_run_section = True
            if in_run_section and "REG_SZ" in line:
                run_keys.append(line.strip())
                for sus in SUSPICIOUS_PROCESS_NAMES + [".exe"]:
                    if sus in line.lower():
                        self._add_finding(
                            "HIGH", "PERSISTENCE",
                            "Suspicious registry Run key value",
                            f"Registry autostart: {line.strip()}",
                            "registry_run",
                            evidence=line
                        )
                        break

        if run_keys:
            self._add_finding(
                "MEDIUM", "PERSISTENCE",
                f"Registry autostart keys found ({len(run_keys)})",
                "These may indicate persistence mechanisms.\n" + "\n".join(run_keys[:10]),
                "registry_run"
            )

    def analyze_credentials(self):
        log("STEP", "Analyzing credential artifacts …")
        hashdump_text = self._output("hashdump")
        if hashdump_text.strip() and "[ERROR" not in hashdump_text:
            hashes = [l for l in hashdump_text.splitlines()
                      if re.match(r"\w+:\d+:[0-9a-f]{32}:", l, re.IGNORECASE)]
            if hashes:
                self._add_finding(
                    "HIGH", "CREDENTIAL",
                    f"Password hashes dumped from memory ({len(hashes)} accounts)",
                    "SAM database hashes found in memory. NTLM hashes exposed.",
                    "hashdump",
                    evidence="\n".join(hashes[:5]) + "\n[truncated]"
                )
        cachedump_text = self._output("cachedump")
        if cachedump_text.strip() and "[ERROR" not in cachedump_text:
            self._add_finding(
                "HIGH", "CREDENTIAL",
                "Cached domain credentials found in memory",
                "Domain credential cache (mscache) exposed.",
                "credential_dump",
                evidence=cachedump_text[:500]
            )

    def analyze_services(self):
        log("STEP", "Analyzing services …")
        text = self._output("svcscan")
        if not text.strip():
            return
        suspicious_svcs = []
        for line in text.splitlines():
            line_low = line.lower()
            for sus in SUSPICIOUS_PROCESS_NAMES:
                if sus in line_low:
                    suspicious_svcs.append(line.strip())
            for sus_path in SUSPICIOUS_PATHS:
                if sus_path in line_low and ".exe" in line_low:
                    suspicious_svcs.append(line.strip())

        if suspicious_svcs:
            self._add_finding(
                "HIGH", "PERSISTENCE",
                f"Suspicious services detected ({len(suspicious_svcs)})",
                "\n".join(suspicious_svcs[:10]),
                "service_persistence",
                evidence="\n".join(suspicious_svcs[:10])
            )

    def analyze_dlllist(self):
        log("STEP", "Analyzing DLL lists …")
        text = self._output("dlllist")
        if not text.strip():
            return

        current_proc = ""
        anonymous_dlls = []

        for line in text.splitlines():
            pm = re.match(r"(?:\*+\s+)?(.+?)\s+pid:\s*(\d+)", line, re.IGNORECASE)
            if pm:
                current_proc = pm.group(1).strip()
                continue
            # DLLs without backing path (anonymous / injected)
            if re.match(r"0x[0-9a-f]+\s+0x[0-9a-f]+\s+\d+\s+\d+\s+\S*\s+\S*\s*$", line, re.IGNORECASE):
                anonymous_dlls.append(f"{current_proc}: {line.strip()}")

        if anonymous_dlls:
            self._add_finding(
                "HIGH", "INJECTION",
                f"DLLs with no backing file ({len(anonymous_dlls)})",
                "Possible manually-mapped / reflectively-injected DLLs.\n" +
                "\n".join(anonymous_dlls[:10]),
                "dll_injection",
                evidence="\n".join(anonymous_dlls[:10])
            )

    def analyze_cmdline(self):
        log("STEP", "Analyzing command lines …")
        text = self._output("cmdline")
        if not text.strip():
            return

        for line in text.splitlines():
            line_low = line.lower()
            # powershell encoded commands
            if "powershell" in line_low and ("-enc" in line_low or "-encodedcommand" in line_low
                                              or "-e " in line_low or "base64" in line_low):
                self._add_finding(
                    "HIGH", "EXECUTION",
                    "PowerShell encoded command detected",
                    f"Obfuscated PowerShell execution: {line.strip()[:200]}",
                    "process_injection",
                    evidence=line
                )
            # wscript / cscript / mshta
            for sus in ["mshta", "wscript", "cscript", "regsvr32", "rundll32", "certutil -decode",
                        "bitsadmin", "wmic process call create", "cmd /c"]:
                if sus in line_low:
                    self._add_finding(
                        "MEDIUM", "EXECUTION",
                        f"LOLBin / suspicious command: {sus}",
                        line.strip()[:300],
                        "process_injection",
                        evidence=line
                    )
                    break

    def analyze_envars(self):
        log("STEP", "Analyzing environment variables …")
        text = self._output("envars")
        for line in text.splitlines():
            if re.search(r"(COMSPEC|PATH|SYSTEMROOT|TEMP)", line, re.IGNORECASE):
                for sus_path in SUSPICIOUS_PATHS:
                    if sus_path in line.lower():
                        self._add_finding(
                            "MEDIUM", "EVASION",
                            "Suspicious environment variable path",
                            line.strip()[:200],
                            "env_manipulation",
                            evidence=line
                        )
                        break

    def analyze_userassist(self):
        log("STEP", "Analyzing UserAssist artifacts …")
        text = self._output("userassist")
        if not text.strip():
            return
        for line in text.splitlines():
            line_low = line.lower()
            for sus in SUSPICIOUS_PROCESS_NAMES:
                if sus in line_low:
                    self._add_finding(
                        "HIGH", "EXECUTION",
                        f"Suspicious UserAssist entry: {sus}",
                        line.strip()[:300],
                        "userassist",
                        evidence=line
                    )

    def analyze_handles(self):
        log("STEP", "Analyzing handles for lsass access …")
        text = self._output("handles")
        lsass_handles = []
        for line in text.splitlines():
            if "lsass" in line.lower() and "process" in line.lower():
                lsass_handles.append(line.strip())
        if lsass_handles:
            self._add_finding(
                "CRITICAL", "CREDENTIAL",
                f"Process handle(s) open to lsass.exe ({len(lsass_handles)})",
                "Another process has an open handle to lsass — potential credential theft.",
                "lsass_access",
                evidence="\n".join(lsass_handles[:5])
            )

    def analyze_callbacks(self):
        log("STEP", "Analyzing kernel callbacks …")
        text = self._output("callbacks")
        if not text.strip():
            return
        unknown_callbacks = []
        for line in text.splitlines():
            if re.search(r"0x[0-9a-f]{8,}", line, re.IGNORECASE):
                # callbacks not pointing to known system modules
                if not any(m in line.lower() for m in
                           ["ntoskrnl", "hal.dll", "win32k", "ndis", "tcpip", "netio"]):
                    unknown_callbacks.append(line.strip())
        if unknown_callbacks:
            self._add_finding(
                "HIGH", "ROOTKIT",
                f"Unknown kernel callbacks ({len(unknown_callbacks)})",
                "Callbacks registered by unknown modules may indicate rootkit.",
                "kernel_hook",
                evidence="\n".join(unknown_callbacks[:10])
            )

    def build_timeline(self):
        log("STEP", "Building event timeline …")
        text = self._output("timeliner") or ""
        for line in text.splitlines():
            # timeliner format: DATETIME | Plugin | Data
            m = re.match(r"(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s*\|\s*(\S+)\s*\|\s*(.+)", line)
            if m:
                self._add_timeline(m.group(1), m.group(2), m.group(3).strip())

        # also pull timestamps from pslist
        pslist_text = self._output("pslist")
        for line in pslist_text.splitlines():
            m = re.search(r"(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+UTC[+-]?\d*", line)
            if m:
                parts = line.split()
                if len(parts) >= 2:
                    self._add_timeline(m.group(1), "pslist", f"Process: {parts[1] if len(parts) > 1 else line[:40]}")

        self.timeline.sort(key=lambda x: x["ts"])
        self._add_finding("INFO", "TIMELINE",
                          f"Timeline entries: {len(self.timeline)}",
                          "Timeline reconstruction complete.")

    def run_all(self):
        log("STEP", f"{C.CYAN}═══ Starting Automated Analysis ═══{C.RESET}")
        self.analyze_processes()
        self.analyze_malfind()
        self.analyze_network()
        self.analyze_ssdt()
        self.analyze_modules()
        self.analyze_registry()
        self.analyze_credentials()
        self.analyze_services()
        self.analyze_dlllist()
        self.analyze_cmdline()
        self.analyze_envars()
        self.analyze_userassist()
        self.analyze_handles()
        self.analyze_callbacks()
        self.build_timeline()
        log("OK", f"Analysis complete. Total findings: {C.BOLD}{len(self.findings)}{C.RESET}")


# ─────────────────────────────────────────────────────────────────────────────
# REPORT GENERATION
# ─────────────────────────────────────────────────────────────────────────────
class ReportGenerator:
    def __init__(self, engine: AnalysisEngine, meta: dict, output_dir: str):
        self.engine     = engine
        self.meta       = meta
        self.output_dir = output_dir
        # make results accessible for plugin output section
        if not hasattr(engine, 'results'):
            engine.results = {}

    # ── severity helpers ──────────────────────────────────────────────────────
    def _sev_color(self, sev):
        return {"CRITICAL": "#ff4757", "HIGH": "#ff6b35",
                "MEDIUM":   "#ffa502", "LOW":  "#2ed573",
                "INFO":     "#747d8c"}.get(sev, "#aaa")

    def _sev_badge(self, sev):
        col = self._sev_color(sev)
        return (f'<span style="background:{col};color:#fff;padding:2px 8px;'
                f'border-radius:4px;font-size:11px;font-weight:bold;">{sev}</span>')

    # ── JSON report ───────────────────────────────────────────────────────────
    def save_json(self):
        out = {
            "meta":     self.meta,
            "findings": self.engine.findings,
            "mitre":    self.engine.mitre_hits,
            "timeline": self.engine.timeline,
            "network":  self.engine.network_table,
        }
        path = os.path.join(self.output_dir, "report.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(out, f, indent=2)
        log("OK", f"JSON report → {path}")

    # ── HTML report ───────────────────────────────────────────────────────────
    def save_html(self):
        findings = self.engine.findings
        mitre    = {m["id"] for m in self.engine.mitre_hits}
        timeline = self.engine.timeline
        network  = self.engine.network_table

        sev_counts = defaultdict(int)
        for f in findings:
            sev_counts[f["severity"]] += 1

        def findings_table(items):
            rows = ""
            for f in items:
                mitre_cell = ""
                if "mitre_id" in f:
                    mitre_cell = (f'<code style="font-size:11px">{f["mitre_id"]}</code> '
                                  f'{f.get("mitre_name","")}<br>'
                                  f'<small>{f.get("mitre_tactic","")}</small>')
                ev = f.get("evidence", "").replace("<", "&lt;").replace(">", "&gt;")
                detail = f["detail"].replace("<", "&lt;").replace(">", "&gt;")
                rows += f"""
                <tr>
                  <td>{self._sev_badge(f['severity'])}</td>
                  <td><b>{f['category']}</b></td>
                  <td>{f['title']}</td>
                  <td style="font-size:12px;white-space:pre-wrap">{detail}</td>
                  <td style="font-size:11px">{mitre_cell}</td>
                  <td><details><summary>Show</summary><pre style="font-size:10px;max-height:150px;overflow:auto">{ev}</pre></details></td>
                </tr>"""
            return rows

        mitre_cards = ""
        seen = set()
        for m in self.engine.mitre_hits:
            if m["id"] not in seen:
                seen.add(m["id"])
                mitre_cards += f"""
                <div class="mitre-card">
                  <div class="mitre-id">{m['id']}</div>
                  <div class="mitre-name">{m['name']}</div>
                  <div class="mitre-tactic">{m['tactic']}</div>
                </div>"""

        timeline_rows = ""
        for t in timeline[:200]:
            timeline_rows += (f"<tr><td>{t['ts']}</td><td>{t['plugin']}</td>"
                              f"<td>{t['event'][:120]}</td></tr>\n")

        net_rows = ""
        for c in network[:100]:
            net_rows += (f"<tr><td>{c['proto']}</td>"
                         f"<td>{c['local_ip']}:{c['local_port']}</td>"
                         f"<td>{c['remote_ip']}:{c['remote_port']}</td>"
                         f"<td>{c['state']}</td>"
                         f"<td>{c['pid']}</td>"
                         f"<td>{c['owner']}</td></tr>\n")

        # ── plugin output toggles ─────────────────────────────────────────────
        plugin_cards = ""
        for i, (pname, rdata) in enumerate(self.engine.results.items(), 1):
            friendly  = PLUGIN_DISPLAY.get(pname, pname)
            status    = rdata.get("status", "ok")
            elapsed   = rdata.get("elapsed", 0)
            raw_out   = rdata.get("output", "").replace("<", "&lt;").replace(">", "&gt;")
            cmd_str   = rdata.get("cmd", "").replace("<", "&lt;")
            lines     = len(raw_out.splitlines())
            has_out   = bool(raw_out.strip()) and status not in ("error", "timeout")

            status_badge = {
                "ok":      '<span class="badge badge-ok">✔ OK</span>',
                "error":   '<span class="badge badge-err">✘ ERROR</span>',
                "timeout": '<span class="badge badge-warn">⏱ TIMEOUT</span>',
            }.get(status, '<span class="badge badge-ok">OK</span>')

            preview = ""
            if has_out:
                first_lines = "\n".join(raw_out.splitlines()[:6])
                preview = f'<pre class="plugin-preview">{first_lines}</pre>'

            plugin_cards += f"""
            <div class="plugin-card" id="pc-{pname}">
              <div class="plugin-header" onclick="togglePlugin('{pname}')">
                <span class="plugin-num">{i:02d}</span>
                <span class="plugin-arrow" id="arr-{pname}">▶</span>
                <span class="plugin-fname">{friendly}</span>
                <span class="plugin-key">({pname})</span>
                <span class="plugin-spacer"></span>
                {status_badge}
                <span class="plugin-meta">{elapsed}s · {lines} lines</span>
              </div>
              <div class="plugin-body" id="pb-{pname}" style="display:none">
                <div class="plugin-cmd">$ {cmd_str}</div>
                {preview}
                <details>
                  <summary class="full-output-btn">📄 Show full output ({lines} lines)</summary>
                  <pre class="plugin-full">{raw_out if raw_out.strip() else "(no output)"}</pre>
                </details>
              </div>
            </div>"""

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Memory Forensics Report — {self.meta.get('image_file','')}</title>
  <style>
    :root {{
      --bg: #0d1117; --surface: #161b22; --border: #30363d;
      --text: #c9d1d9; --muted: #8b949e; --accent: #58a6ff;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ background: var(--bg); color: var(--text); font-family: 'Segoe UI',sans-serif;
           font-size: 14px; line-height: 1.6; }}
    .header {{ background: linear-gradient(135deg,#1a1f35,#0d1117);
               border-bottom: 2px solid var(--accent); padding: 30px 40px; }}
    .header h1 {{ color: #58a6ff; font-size: 26px; }}
    .header p  {{ color: var(--muted); margin-top: 6px; font-size: 12px; }}
    .container {{ max-width: 1400px; margin: 0 auto; padding: 24px 32px; }}
    h2 {{ color: var(--accent); border-bottom: 1px solid var(--border);
          padding-bottom: 8px; margin: 32px 0 16px; font-size: 18px; }}
    .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px,1fr));
              gap: 16px; margin-bottom: 24px; }}
    .stat {{ background: var(--surface); border: 1px solid var(--border);
             border-radius: 8px; padding: 16px; text-align: center; }}
    .stat .num  {{ font-size: 32px; font-weight: bold; }}
    .stat .lbl  {{ color: var(--muted); font-size: 12px; margin-top: 4px; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
    th {{ background: var(--surface); color: var(--accent); text-align: left;
          padding: 10px 12px; border-bottom: 1px solid var(--border);
          position: sticky; top: 0; }}
    td {{ padding: 8px 12px; border-bottom: 1px solid var(--border);
          vertical-align: top; }}
    tr:hover td {{ background: rgba(88,166,255,.05); }}
    code {{ background: #1e2430; padding: 1px 5px; border-radius: 3px;
            font-family: monospace; color: #79c0ff; }}
    pre  {{ background: #0d1117; border: 1px solid var(--border); border-radius: 6px;
            padding: 12px; font-family: monospace; font-size: 11px;
            white-space: pre-wrap; word-break: break-all; }}
    .mitre-grid {{ display: grid; grid-template-columns: repeat(auto-fill,minmax(200px,1fr));
                   gap: 12px; }}
    .mitre-card {{ background: var(--surface); border: 1px solid var(--border);
                   border-radius: 8px; padding: 14px; }}
    .mitre-id   {{ font-weight: bold; color: #ff79c6; font-size: 15px; }}
    .mitre-name {{ color: var(--text); font-size: 13px; margin-top: 4px; }}
    .mitre-tactic {{ color: var(--muted); font-size: 11px; margin-top: 2px; }}
    .meta-grid  {{ display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }}
    .meta-item  {{ background: var(--surface); border: 1px solid var(--border);
                   border-radius: 6px; padding: 12px; }}
    .meta-key   {{ color: var(--muted); font-size: 11px; text-transform: uppercase; }}
    .meta-val   {{ color: var(--text); font-size: 14px; margin-top: 3px;
                   font-family: monospace; word-break: break-all; }}
    details summary {{ cursor: pointer; color: var(--accent); font-size:12px; }}
    .section    {{ background: var(--surface); border: 1px solid var(--border);
                   border-radius: 10px; padding: 20px; margin-bottom: 24px; overflow: auto; }}
    .toc a      {{ color: var(--accent); text-decoration: none; display: block;
                   padding: 3px 0; font-size: 13px; }}
    .toc a:hover {{ text-decoration: underline; }}

    /* ── Plugin Cards ───────────────────────────────────── */
    .plugin-card {{
      border: 1px solid var(--border); border-radius: 8px;
      margin-bottom: 8px; overflow: hidden;
      transition: border-color .2s;
    }}
    .plugin-card:hover {{ border-color: var(--accent); }}
    .plugin-header {{
      display: flex; align-items: center; gap: 10px;
      padding: 10px 16px; cursor: pointer;
      background: var(--surface);
      user-select: none;
    }}
    .plugin-header:hover {{ background: #1c2333; }}
    .plugin-num  {{ color: var(--muted); font-size: 12px; min-width: 28px;
                    font-family: monospace; }}
    .plugin-arrow {{ color: var(--accent); font-size: 13px; transition: transform .2s;
                     min-width: 14px; }}
    .plugin-arrow.open {{ transform: rotate(90deg); }}
    .plugin-fname {{ color: var(--text); font-weight: 600; font-size: 14px; }}
    .plugin-key   {{ color: var(--muted); font-size: 12px; font-family: monospace; }}
    .plugin-spacer {{ flex: 1; }}
    .plugin-meta  {{ color: var(--muted); font-size: 11px; }}
    .badge {{ padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; }}
    .badge-ok   {{ background: #1a3a1a; color: #2ed573; border: 1px solid #2ed573; }}
    .badge-err  {{ background: #3a1a1a; color: #ff4757; border: 1px solid #ff4757; }}
    .badge-warn {{ background: #3a2a00; color: #ffa502; border: 1px solid #ffa502; }}
    .plugin-body  {{
      border-top: 1px solid var(--border);
      background: #0d1117; padding: 16px;
    }}
    .plugin-cmd   {{
      font-family: monospace; font-size: 11px; color: #79c0ff;
      background: #1a1f2e; border-radius: 4px; padding: 8px 12px;
      margin-bottom: 10px; word-break: break-all;
    }}
    .plugin-preview {{
      border: 1px solid #21262d; border-radius: 4px;
      padding: 8px 12px; max-height: 140px; overflow: auto;
      font-size: 11px; margin-bottom: 10px; color: #8b949e;
    }}
    .plugin-full  {{ max-height: 500px; overflow: auto; font-size: 11px; }}
    .full-output-btn {{
      color: var(--accent) !important; font-size: 12px;
      cursor: pointer; padding: 4px 0; display: inline-block;
    }}
    .plugin-toolbar {{
      display: flex; gap: 8px; margin-bottom: 12px; flex-wrap: wrap;
    }}
    .btn-sm {{
      padding: 4px 12px; border-radius: 4px; border: 1px solid var(--border);
      background: var(--surface); color: var(--accent);
      cursor: pointer; font-size: 12px;
    }}
    .btn-sm:hover {{ background: #1c2333; }}
    .filter-bar {{ display: flex; gap: 8px; margin-bottom: 12px; flex-wrap: wrap; }}
    .filter-btn {{ padding: 5px 14px; border-radius: 20px; border: 1px solid var(--border);
                   background: transparent; color: var(--muted); cursor: pointer; font-size: 12px; }}
    .filter-btn.active {{ background: var(--accent); color: #fff; border-color: var(--accent); }}
  </style>
</head>
<body>
  <div class="header">
    <h1>🔬 Memory Forensics Investigation Report</h1>
    <p>Generated: {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")} &nbsp;|&nbsp;
       Image: <code>{self.meta.get('image_file','')}</code> &nbsp;|&nbsp;
       SHA256: <code>{self.meta.get('sha256','')}</code> &nbsp;|&nbsp;
       Profile: <code>{self.meta.get('profile','')}</code></p>
  </div>
  <div class="container">
    <!-- TOC -->
    <h2>📋 Table of Contents</h2>
    <div class="section toc">
      <a href="#meta">1. Case Metadata</a>
      <a href="#summary">2. Executive Summary</a>
      <a href="#findings">3. Findings</a>
      <a href="#mitre">4. MITRE ATT&CK Coverage</a>
      <a href="#network">5. Network Connections</a>
      <a href="#timeline">6. Event Timeline</a>
      <a href="#plugins">7. Plugin Outputs</a>
    </div>

    <!-- META -->
    <h2 id="meta">📁 Case Metadata</h2>
    <div class="section">
      <div class="meta-grid">
        {"".join(f'<div class="meta-item"><div class="meta-key">{k}</div><div class="meta-val">{v}</div></div>'
                 for k,v in self.meta.items())}
      </div>
    </div>

    <!-- SUMMARY -->
    <h2 id="summary">📊 Executive Summary</h2>
    <div class="section">
      <div class="stats">
        <div class="stat"><div class="num" style="color:#ff4757">{sev_counts['CRITICAL']}</div><div class="lbl">CRITICAL</div></div>
        <div class="stat"><div class="num" style="color:#ff6b35">{sev_counts['HIGH']}</div><div class="lbl">HIGH</div></div>
        <div class="stat"><div class="num" style="color:#ffa502">{sev_counts['MEDIUM']}</div><div class="lbl">MEDIUM</div></div>
        <div class="stat"><div class="num" style="color:#2ed573">{sev_counts['LOW']}</div><div class="lbl">LOW</div></div>
        <div class="stat"><div class="num" style="color:#58a6ff">{len(findings)}</div><div class="lbl">TOTAL FINDINGS</div></div>
        <div class="stat"><div class="num" style="color:#a29bfe">{len(seen)}</div><div class="lbl">MITRE TECHNIQUES</div></div>
        <div class="stat"><div class="num" style="color:#74b9ff">{len(network)}</div><div class="lbl">CONNECTIONS</div></div>
        <div class="stat"><div class="num" style="color:#fd79a8">{len(timeline)}</div><div class="lbl">TIMELINE EVENTS</div></div>
      </div>
    </div>

    <!-- FINDINGS -->
    <h2 id="findings">🚨 Findings</h2>
    <div class="section">
      <table>
        <thead>
          <tr><th>Severity</th><th>Category</th><th>Title</th><th>Detail</th><th>MITRE</th><th>Evidence</th></tr>
        </thead>
        <tbody>
          {findings_table(findings)}
        </tbody>
      </table>
    </div>

    <!-- MITRE -->
    <h2 id="mitre">🛡 MITRE ATT&CK Coverage</h2>
    <div class="section">
      <div class="mitre-grid">
        {mitre_cards if mitre_cards else '<p style="color:var(--muted)">No MITRE techniques mapped.</p>'}
      </div>
    </div>

    <!-- NETWORK -->
    <h2 id="network">🌐 Network Connections</h2>
    <div class="section">
      <table>
        <thead><tr><th>Proto</th><th>Local</th><th>Remote</th><th>State</th><th>PID</th><th>Owner</th></tr></thead>
        <tbody>{net_rows if net_rows else '<tr><td colspan="6" style="color:var(--muted);text-align:center">No connections parsed.</td></tr>'}</tbody>
      </table>
    </div>

    <!-- TIMELINE -->
    <h2 id="timeline">⏱ Event Timeline</h2>
    <div class="section">
      <table>
        <thead><tr><th>Timestamp</th><th>Source</th><th>Event</th></tr></thead>
        <tbody>{timeline_rows if timeline_rows else '<tr><td colspan="3" style="color:var(--muted);text-align:center">No timeline events.</td></tr>'}</tbody>
      </table>
    </div>

    <!-- PLUGIN OUTPUTS -->
    <h2 id="plugins">🔌 Plugin Outputs</h2>
    <div class="section" style="padding:16px">
      <div class="plugin-toolbar">
        <button class="btn-sm" onclick="expandAll()">▼ Expand All</button>
        <button class="btn-sm" onclick="collapseAll()">▲ Collapse All</button>
        <button class="btn-sm" onclick="filterPlugins('all')" id="fb-all">All</button>
        <button class="btn-sm" onclick="filterPlugins('ok')"  id="fb-ok">✔ OK</button>
        <button class="btn-sm" onclick="filterPlugins('err')" id="fb-err">✘ Error</button>
        <input type="text" id="plugin-search" placeholder="🔍 Filter plugins…"
               oninput="searchPlugins(this.value)"
               style="padding:4px 10px;border-radius:4px;border:1px solid var(--border);
                      background:var(--bg);color:var(--text);font-size:12px;margin-left:8px;">
      </div>
      <div id="plugin-list">
        {plugin_cards}
      </div>
    </div>

  </div>

  <script>
    function togglePlugin(name) {{
      const body = document.getElementById('pb-' + name);
      const arr  = document.getElementById('arr-' + name);
      const open = body.style.display !== 'none';
      body.style.display = open ? 'none' : 'block';
      arr.classList.toggle('open', !open);
    }}
    function expandAll() {{
      document.querySelectorAll('[id^="pb-"]').forEach(el => el.style.display = 'block');
      document.querySelectorAll('[id^="arr-"]').forEach(el => el.classList.add('open'));
    }}
    function collapseAll() {{
      document.querySelectorAll('[id^="pb-"]').forEach(el => el.style.display = 'none');
      document.querySelectorAll('[id^="arr-"]').forEach(el => el.classList.remove('open'));
    }}
    function searchPlugins(q) {{
      q = q.toLowerCase();
      document.querySelectorAll('.plugin-card').forEach(card => {{
        const text = card.innerText.toLowerCase();
        card.style.display = text.includes(q) ? '' : 'none';
      }});
    }}
    function filterPlugins(mode) {{
      document.querySelectorAll('.plugin-card').forEach(card => {{
        if (mode === 'all') {{ card.style.display = ''; return; }}
        const hasErr = card.querySelector('.badge-err') !== null;
        card.style.display = (mode === 'err' ? hasErr : !hasErr) ? '' : 'none';
      }});
    }}
  </script>
</body>
</html>"""

        path = os.path.join(self.output_dir, "report.html")
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)
        log("OK", f"HTML report → {path}")

    def save_text_summary(self):
        lines = [
            "=" * 80,
            "  MEMORY FORENSICS ANALYSIS SUMMARY",
            f"  Image    : {self.meta.get('image_file','')}",
            f"  SHA256   : {self.meta.get('sha256','')}",
            f"  Profile  : {self.meta.get('profile','')}",
            f"  Generated: {datetime.datetime.now().isoformat()}",
            "=" * 80, ""
        ]
        sev_counts = defaultdict(int)
        for f in self.engine.findings:
            sev_counts[f["severity"]] += 1

        lines += [
            "SEVERITY SUMMARY",
            f"  CRITICAL : {sev_counts['CRITICAL']}",
            f"  HIGH     : {sev_counts['HIGH']}",
            f"  MEDIUM   : {sev_counts['MEDIUM']}",
            f"  LOW      : {sev_counts['LOW']}",
            f"  INFO     : {sev_counts['INFO']}",
            f"  TOTAL    : {len(self.engine.findings)}",
            "",
        ]

        lines.append("FINDINGS")
        lines.append("-" * 80)
        for f in self.engine.findings:
            lines.append(f"[{f['severity']:8s}] [{f['category']:12s}] {f['title']}")
            lines.append(f"           {f['detail'][:120]}")
            if "mitre_id" in f:
                lines.append(f"           MITRE: {f['mitre_id']} {f.get('mitre_name','')} — {f.get('mitre_tactic','')}")
            lines.append("")

        lines.append("MITRE ATT&CK TECHNIQUES OBSERVED")
        lines.append("-" * 80)
        seen = set()
        for m in self.engine.mitre_hits:
            if m["id"] not in seen:
                seen.add(m["id"])
                lines.append(f"  {m['id']:12s} {m['name']:40s} [{m['tactic']}]")

        path = os.path.join(self.output_dir, "report_summary.txt")
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        log("OK", f"Text summary → {path}")

    def save_all(self):
        self.save_json()
        self.save_html()
        self.save_text_summary()


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────
def parse_args():
    p = argparse.ArgumentParser(
        description="Volatility Memory Forensics Automation & Analysis Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Volatility 2 — auto-detect profile
  python3 vol_analyzer.py -f memory.vmem --vol2 /opt/volatility/vol.py --auto-profile

  # Volatility 2 — specify profile
  python3 vol_analyzer.py -f memory.raw --vol2 vol.py --profile Win7SP1x64

  # Volatility 3
  python3 vol_analyzer.py -f memory.vmem --vol3 vol3 --os windows

  # With YARA rules
  python3 vol_analyzer.py -f memory.raw --vol2 vol.py --profile Win10x64 --yara-rules malware.yar

  # Skip slow plugins, limit handles
  python3 vol_analyzer.py -f memory.raw --vol2 vol.py --profile Win7SP1x64 \\
      --skip memmap driverirp --timeout 600
"""
    )
    p.add_argument("-f", "--file",        required=True, help="Path to memory image")
    p.add_argument("--vol2",              default="",   help="Path to volatility.py (Vol2)")
    p.add_argument("--vol3",              default="",   help="Path to vol.py (Vol3)")
    p.add_argument("--profile",           default="",   help="Vol2 profile (e.g. Win7SP1x64)")
    p.add_argument("--auto-profile",      action="store_true", help="Auto-detect profile via imageinfo")
    p.add_argument("--os",                default="windows", choices=["windows","linux","mac"],
                   help="OS type for Vol3 plugin prefix")
    p.add_argument("--output-dir", "-o",  default="", help="Output directory (default: <image>_forensics/)")
    p.add_argument("--yara-rules",        default="", help="YARA rules file for yarascan")
    p.add_argument("--skip",              nargs="*", default=[], help="Plugins to skip")
    p.add_argument("--only",              nargs="*", default=[], help="Run ONLY these plugins")
    p.add_argument("--timeout",           type=int, default=300, help="Per-plugin timeout (seconds)")
    p.add_argument("--threads",           type=int, default=1,   help="Parallel plugin threads (experimental)")
    p.add_argument("--no-analysis",       action="store_true", help="Skip automated analysis")
    p.add_argument("--no-report",         action="store_true", help="Skip report generation")
    p.add_argument("--printkey-path",     default=r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                   help="Registry key path for printkey plugin")
    return p.parse_args()


def main():
    banner()
    args = parse_args()

    # ── validate inputs ────────────────────────────────────────────────────────
    if not os.path.isfile(args.file):
        log("CRIT", f"Memory file not found: {args.file}")
        sys.exit(1)
    if not args.vol2 and not args.vol3:
        log("CRIT", "Specify --vol2 or --vol3 (path to Volatility binary)")
        sys.exit(1)

    vol_version = 2 if args.vol2 else 3
    vol_bin     = args.vol2 if args.vol2 else args.vol3

    # ── Auto-detect if user passed the wrong --vol2/--vol3 flag ───────────────
    # Read the first 4KB of the script to check which version it actually is
    if vol_bin.lower().endswith(".py") and os.path.isfile(vol_bin):
        try:
            with open(vol_bin, "r", encoding="utf-8", errors="replace") as _vf:
                _head = _vf.read(4096).lower()
            _is_vol3_script = ("volatility3" in _head or "vol3" in _head
                               or "from volatility" in _head
                               or "import volatility" in _head)
            _is_vol2_script = ("volatility.conf" in _head or "MemoryRegistry" in _head.lower()
                               or "addrspace" in _head)
            if vol_version == 3 and _is_vol2_script and not _is_vol3_script:
                log("WARN", f"{C.RED}⚠ MISMATCH DETECTED:{C.RESET} You used {C.BOLD}--vol3{C.RESET} "
                    f"but {C.BOLD}{vol_bin}{C.RESET} looks like a {C.BOLD}Volatility 2{C.RESET} script.")
                log("WARN", f"  {C.YELLOW}Fix: use  --vol2 {vol_bin} --profile Win7SP1x64  instead{C.RESET}")
            elif vol_version == 2 and _is_vol3_script and not _is_vol2_script:
                log("WARN", f"{C.RED}⚠ MISMATCH DETECTED:{C.RESET} You used {C.BOLD}--vol2{C.RESET} "
                    f"but {C.BOLD}{vol_bin}{C.RESET} looks like a {C.BOLD}Volatility 3{C.RESET} script.")
                log("WARN", f"  {C.YELLOW}Fix: use  --vol3 {vol_bin}  instead{C.RESET}")
        except Exception:
            pass

    # ── output directory ───────────────────────────────────────────────────────
    if args.output_dir:
        output_dir = args.output_dir
    else:
        base = os.path.splitext(os.path.basename(args.file))[0]
        output_dir = f"{base}_forensics_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
    os.makedirs(output_dir, exist_ok=True)
    log("INFO", f"Output directory: {C.BOLD}{output_dir}{C.RESET}")

    # ── hash the image ─────────────────────────────────────────────────────────
    log("INFO", "Hashing memory image (SHA-256) …")
    image_sha = sha256(args.file)
    log("OK",   f"SHA-256: {image_sha}")

    # ── determine profile ──────────────────────────────────────────────────────
    profile = args.profile
    if vol_version == 2 and (not profile or args.auto_profile):
        profile = detect_profile(vol_bin, args.file, vol_version, output_dir, args.timeout)
    elif vol_version == 3:
        profile = "auto"

    log("INFO", f"Using profile: {C.BOLD}{profile}{C.RESET}")

    # ── build plugin list ──────────────────────────────────────────────────────
    if args.only:
        plugins_to_run = args.only
    else:
        plugins_to_run = list(VOL2_PLUGINS if vol_version == 2 else VOL3_PLUGINS.keys())
        # remove yarascan if no rules provided
        if not args.yara_rules and "yarascan" in plugins_to_run:
            plugins_to_run.remove("yarascan")
        # skip requested plugins
        plugins_to_run = [p for p in plugins_to_run if p not in args.skip]

    log("INFO", f"Plugins to run: {C.BOLD}{len(plugins_to_run)}{C.RESET}")
    print()

    # ── run all plugins ────────────────────────────────────────────────────────
    all_results = {}
    total = len(plugins_to_run)
    print(f"{C.CYAN}{C.BOLD}{'─'*60}{C.RESET}")
    print(f"{C.CYAN}{C.BOLD}  PHASE 1 — PLUGIN EXECUTION ({total} plugins){C.RESET}")
    print(f"{C.CYAN}{C.BOLD}{'─'*60}{C.RESET}\n")

    i = 0
    try:
        for i, plugin in enumerate(plugins_to_run, 1):
            extra = []
            if vol_version == 2:
                if plugin == "printkey":
                    extra = ["-K", args.printkey_path]
                elif plugin == "yarascan" and args.yara_rules:
                    extra = ["--yara-file", args.yara_rules]
            else:  # vol3
                if plugin == "yarascan" and args.yara_rules:
                    extra = ["--yara-file", args.yara_rules]
                if plugin == "printkey":
                    extra = ["--key", args.printkey_path]

            r = run_plugin(vol_bin, args.file, plugin,
                           profile, extra, output_dir,
                           vol_version, args.timeout,
                           step_num=i, total=total)
            all_results[plugin] = r

    except KeyboardInterrupt:
        print()
        print(f"  {C.YELLOW}{C.BOLD}⏹  Interrupted by user (Ctrl+C){C.RESET}")
        done = len(all_results)
        skipped = plugins_to_run[done:]
        if skipped:
            print(f"  {C.DIM}Skipped {len(skipped)} remaining plugin(s): "
                  f"{', '.join(skipped[:8])}{'…' if len(skipped) > 8 else ''}{C.RESET}")
        print(f"  {C.DIM}Generating partial report from {done} completed plugin(s)…{C.RESET}\n")

    # ── Post-run sanity check: warn if most plugins failed ────────────────────
    warn_count = sum(1 for r in all_results.values()
                     if r.get("status") in ("warn", "error", "timeout"))
    ok_count   = len(all_results) - warn_count
    print()
    if warn_count > 0:
        pct = int(warn_count / len(all_results) * 100)
        bar_ok  = "█" * min(ok_count, 40)
        bar_bad = "░" * min(warn_count, 40)
        print(f"  {C.CYAN}Plugin Results:{C.RESET}  "
              f"{C.GREEN}{bar_ok}{C.RESET}{C.YELLOW}{bar_bad}{C.RESET}  "
              f"{C.GREEN}✔ {ok_count} OK{C.RESET}  {C.YELLOW}⚠ {warn_count} warned/failed{C.RESET}  "
              f"({pct}% failure rate)")

        # ── Detect the PageMapScanner / no kernel structures pattern ──────────
        pagemapper_hits = sum(
            1 for r in all_results.values()
            if "pagemapscanner" in r.get("output","").lower()
            and "0.00" in r.get("output","")
        )
        usage_hits = sum(
            1 for r in all_results.values()
            if r.get("output","").strip().lower().startswith("usage:")
        )

        if pagemapper_hits >= 3 and pct >= 60:
            print()
            print(f"  {C.YELLOW}{C.BOLD}╔══════════════════════════════════════════════════════════════╗{C.RESET}")
            print(f"  {C.YELLOW}{C.BOLD}║  ROOT CAUSE: Missing Volatility 3 Symbol Pack               ║{C.RESET}")
            print(f"  {C.YELLOW}{C.BOLD}╚══════════════════════════════════════════════════════════════╝{C.RESET}")
            print()
            print(f"  {C.WHITE}Vol3 found and opened the image but could NOT locate kernel{C.RESET}")
            print(f"  {C.WHITE}structures. This means the symbol table for your OS is missing.{C.RESET}")
            print()
            print(f"  {C.GREEN}HOW TO FIX:{C.RESET}")
            print(f"  {C.BOLD}  Step 1:{C.RESET} Identify the exact Windows version from the image:")
            print(f"           python3 {vol_bin} -f {args.file} banners.Banners")
            print()
            print(f"  {C.BOLD}  Step 2:{C.RESET} Download the correct symbol pack (.zip) from:")
            print(f"  {C.CYAN}           https://downloads.volatilityfoundation.org/volatility3/symbols/{C.RESET}")
            print(f"           e.g.  windows.zip  (covers most Windows versions)")
            print()
            print(f"  {C.BOLD}  Step 3:{C.RESET} Extract the .zip into your Vol3 symbols folder:")
            print(f"           volatility3{os.sep}symbols{os.sep}windows{os.sep}   ← put .json.xz files here")
            print()
            print(f"  {C.BOLD}  Step 4:{C.RESET} Re-run the same command — plugins will now find data.")
            print()

        if usage_hits >= 2 and pct >= 60:
            print(f"  {C.DIM}Note: {usage_hits} plugin(s) showed 'usage:' errors → plugin names not{C.RESET}")
            print(f"  {C.DIM}      recognised by your Vol3 build. The script uses full class-path{C.RESET}")
            print(f"  {C.DIM}      names (e.g. windows.pslist.PsList). If errors persist, your{C.RESET}")
            print(f"  {C.DIM}      Vol3 version may not include those plugins.{C.RESET}")
            print()

        if pct >= 60 and pagemapper_hits < 3:
            print()
            print(f"  {C.RED}{C.BOLD}╔══════════════════════════════════════════════════════╗{C.RESET}")
            print(f"  {C.RED}{C.BOLD}║  CRITICAL: {pct:3d}% of plugins returned errors         ║{C.RESET}")
            print(f"  {C.RED}{C.BOLD}║  Most likely cause: wrong Volatility version flag    ║{C.RESET}")
            print(f"  {C.RED}{C.BOLD}╚══════════════════════════════════════════════════════╝{C.RESET}")
            print()
            print(f"  {C.YELLOW}You ran:{C.RESET}  {'--vol3' if vol_version == 3 else '--vol2'} {vol_bin}")
            print()
            print(f"  {C.GREEN}Try instead:{C.RESET}")
            print(f"    {C.BOLD}# Win7 / WinXP / Vista / Server 2008 → Volatility 2:{C.RESET}")
            print(f"      python3 vol_analyzer.py -f {args.file} --vol2 {vol_bin} --auto-profile")
            print(f"      python3 vol_analyzer.py -f {args.file} --vol2 {vol_bin} --profile Win7SP1x64")
            print()
            print(f"    {C.BOLD}# Win10 / Win11 / Server 2016+ → Volatility 3:{C.RESET}")
            print(f"      python3 vol_analyzer.py -f {args.file} --vol3 {vol_bin}")
            print()
            print(f"  {C.DIM}Tip: open any .txt file in the output folder to see the raw error.{C.RESET}")
            print(f"  {C.DIM}Tip: run:  python3 {vol_bin} -f {args.file} windows.info.Info{C.RESET}")
            print()

    # ── automated analysis ─────────────────────────────────────────────────────
    if not args.no_analysis:
        print()
        log("STEP", f"{C.CYAN}{'═'*60}{C.RESET}")
        log("STEP", "Starting automated forensic analysis …")
        engine = AnalysisEngine(all_results, output_dir)
        engine.run_all()
    else:
        engine = AnalysisEngine(all_results, output_dir)

    # ── reports ────────────────────────────────────────────────────────────────
    if not args.no_report:
        print()
        log("STEP", "Generating reports …")
        meta = {
            "image_file":    os.path.abspath(args.file),
            "sha256":        image_sha,
            "profile":       profile,
            "vol_version":   f"Vol{vol_version}",
            "vol_binary":    vol_bin,
            "analysis_date": datetime.datetime.now().isoformat(),
            "plugins_run":   str(len(plugins_to_run)),
            "output_dir":    os.path.abspath(output_dir),
        }
        reporter = ReportGenerator(engine, meta, output_dir)
        reporter.save_all()

    # ── final summary ──────────────────────────────────────────────────────────
    print()
    print(f"{C.CYAN}{'═'*80}{C.RESET}")
    print(f"{C.BOLD}  FORENSIC ANALYSIS COMPLETE{C.RESET}")
    print(f"{'═'*80}")
    print(f"  Image      : {args.file}")
    print(f"  SHA256     : {image_sha}")
    print(f"  Profile    : {profile}")
    print(f"  Plugins run: {len(plugins_to_run)}")
    print(f"  Findings   : {len(engine.findings)}")

    from collections import Counter
    sev_counts = Counter(f["severity"] for f in engine.findings)
    print(f"  CRITICAL   : {C.RED}{sev_counts['CRITICAL']}{C.RESET}")
    print(f"  HIGH       : {C.YELLOW}{sev_counts['HIGH']}{C.RESET}")
    print(f"  MEDIUM     : {C.YELLOW}{sev_counts['MEDIUM']}{C.RESET}")
    print(f"  Output dir : {C.CYAN}{os.path.abspath(output_dir)}{C.RESET}")
    print()

    if not args.no_report:
        print(f"  {C.GREEN}Reports:{C.RESET}")
        print(f"    • HTML  : {os.path.join(output_dir, 'report.html')}")
        print(f"    • JSON  : {os.path.join(output_dir, 'report.json')}")
        print(f"    • Text  : {os.path.join(output_dir, 'report_summary.txt')}")
    print(f"{C.CYAN}{'═'*80}{C.RESET}\n")


if __name__ == "__main__":
    main()