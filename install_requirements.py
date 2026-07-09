#!/usr/bin/env python3
# ==============================================================================
# Forensic Dashboard - Requirements & Prerequisites Installer
# Cross-platform Python helper to set up dependencies.
# ==============================================================================

import sys
import os
import subprocess
import shutil
import platform

SYSTEM_PREREQS = {
    "yara": "YARA scanner (apt: yara, winget: VirusTotal.YARA)",
    "tshark": "Tshark / Wireshark (apt: tshark, winget: Wireshark.Wireshark)",
    "tcpflow": "TCPflow network collector (apt: tcpflow)",
    "zeek": "Zeek network monitor (apt: zeek)",
    "strings": "Strings binary extraction (apt: binutils)",
    "objdump": "Object dump utility (apt: binutils)",
    "readelf": "ELF reader (apt: binutils)",
    "file": "File identification (apt: file)",
    "upx": "UPX executable packer (apt: upx-ucl, winget: UPX.UPX)",
    "bulk_extractor": "Bulk Extractor (apt: bulk-extractor)",
    "dc3dd": "dc3dd imaging tool (apt: dc3dd)",
    "ewfacquire": "EWF acquire tool (apt: ewf-tools)",
    "mysqlbinlog": "MySQL binlog utility (apt: mysql-client)",
    "pt-query-digest": "Percona query digest tool (apt: percona-toolkit)",
    "psql": "PostgreSQL interactive terminal (apt: postgresql-client)",
    "log2timeline.py": "Plaso timeline creation (apt: plaso-tools)",
    "wrestool": "Resource extractor (apt: icoutils)",
    "fls": "SleuthKit fls utility (apt: sleuthkit)",
    "mmls": "SleuthKit mmls utility (apt: sleuthkit)",
}

def check_python_version():
    print(f"[*] Python Version: {platform.python_version()}")
    if sys.version_info < (3, 10):
        print("[-] Warning: Python 3.10+ is recommended.")
    else:
        print("[+] Python version is compatible.")

def install_python_deps():
    print("\n[*] Installing Python dependencies from requirements.txt...")
    req_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "requirements.txt")
    if not os.path.exists(req_file):
        print("[-] Error: requirements.txt not found!")
        return False
    
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", req_file])
        # Also install volatility3
        subprocess.check_call([sys.executable, "-m", "pip", "install", "volatility3"])
        print("[+] Python dependencies installed successfully.")
        return True
    except Exception as e:
        print(f"[-] Error installing Python dependencies: {e}")
        return False

def check_system_prereqs():
    print("\n[*] Checking status of system prerequisites:")
    missing = []
    for prog, desc in SYSTEM_PREREQS.items():
        path = shutil.which(prog)
        if path:
            print(f"  [+] {prog:<16} : Installed ({path})")
        else:
            print(f"  [-] {prog:<16} : Missing - {desc}")
            missing.append(prog)
    return missing

def main():
    print("=========================================================")
    print("     Forensic Dashboard Requirements Installer           ")
    print("=========================================================\n")
    
    check_python_version()
    
    # Run pip install
    install_python_deps()
    
    # Check what is installed
    missing = check_system_prereqs()
    
    current_os = platform.system().lower()
    print(f"\n[*] Current OS: {platform.system()} ({platform.release()})")
    
    if missing:
        print(f"\n[!] Missing {len(missing)} system command-line tool(s).")
        if current_os == "linux":
            # Check if debian/ubuntu
            if os.path.exists("/etc/debian_version"):
                choice = input("\n[?] Debian/Ubuntu detected. Would you like to run install_requirements.sh to install missing packages? (y/n): ")
                if choice.strip().lower() == "y":
                    script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "install_requirements.sh")
                    if os.path.exists(script_path):
                        print("[*] Running install_requirements.sh with sudo...")
                        try:
                            subprocess.check_call(["sudo", "bash", script_path])
                        except Exception as e:
                            print(f"[-] Failed to execute installer script: {e}")
                    else:
                        print("[-] Installer script install_requirements.sh not found!")
            else:
                print("\n[!] Please use your Linux package manager to install the missing tools listed above.")
        elif current_os == "windows":
            print("\n[!] Note: Most digital forensics and malware analysis tools are built for Linux.")
            print("    You can run this dashboard inside Windows Subsystem for Linux (WSL) to use all tools.")
            print("    If you want to run them on Windows, you can install the Windows equivalents:")
            print("    - Wireshark/Tshark: 'winget install Wireshark.Wireshark'")
            print("    - YARA: 'winget install VirusTotal.YARA'")
            print("    - UPX: 'winget install UPX.UPX'")
            print("    - Sleuthkit: Download from https://github.com/sleuthkit/sleuthkit/releases")
    else:
        print("\n[+] All system prerequisites and Python libraries are installed! You are ready to go.")
        
    print("\nTo start the dashboard, run: python app.py")

if __name__ == "__main__":
    main()
