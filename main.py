"""
Simple Keylogger File Detector (Windows)
Usage:
    python main.py --paths "C:\\Users\\Public" "C:\\Windows\\Temp"
If no paths given, it scans current working directory.

Requires: psutil, pefile, tabulate (optional)
Run from an Administrator prompt for best results.
"""
import os
import sys
import argparse
import pefile
import psutil
import subprocess
import winreg
from tabulate import tabulate

# Suspicious API functions commonly used by keyloggers
KEYLOGGER_IMPORTS = {
    "GetAsyncKeyState",
    "GetKeyState",
    "SetWindowsHookExA", "SetWindowsHookExW", "SetWindowsHookEx",
    "CallNextHookEx",
    "GetKeyboardState",
    "RegisterHotKey",
    "GetForegroundWindow",
    "GetWindowTextA", "GetWindowTextW",
}

SUSPICIOUS_NAMES = {"keylogger", "keylog", "klog", "klg", "keyboard", "logkeys", "spy", "logger"}

def scan_pe_for_keys(path):
    """Return set of suspicious imports found (fast, safe read)."""
    found = set()
    try:
        pe = pefile.PE(path, fast_load=True)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
        if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            return found
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.name:
                    name = imp.name.decode(errors='ignore')
                    if name in KEYLOGGER_IMPORTS:
                        found.add(name)
        pe.close()
    except Exception:
        # not a PE or cannot parse -> ignore
        pass
    return found

def scan_files(paths):
    results = []
    for base in paths:
        for root, dirs, files in os.walk(base):
            for f in files:
                full = os.path.join(root, f)
                lower = f.lower()
                name_flag = any(token in lower for token in SUSPICIOUS_NAMES)
                pe_flag_imports = set()
                # check only .exe/.dll/.sys (PE files)
                if lower.endswith(('.exe', '.dll', '.sys')):
                    pe_flag_imports = scan_pe_for_keys(full)
                size = None
                try:
                    size = os.path.getsize(full)
                except Exception:
                    pass
                if name_flag or pe_flag_imports:
                    results.append({
                        "path": full,
                        "name_flag": name_flag,
                        "suspicious_imports": ", ".join(sorted(pe_flag_imports)) if pe_flag_imports else "",
                        "size": size
                    })
    return results

def enumerate_processes():
    procs = []
    for p in psutil.process_iter(['pid','name','exe','cmdline']):
        try:
            info = p.info
            exe = info.get('exe') or ''
            name = info.get('name','')
            cmd = " ".join(info.get('cmdline') or [])
            flags = []
            # check process name similarity
            lname = name.lower() if name else ''
            if any(tok in lname for tok in SUSPICIOUS_NAMES):
                flags.append("name_contains_keylog")
            # attempt to scan executable imports if accessible
            imports = set()
            if exe and os.path.exists(exe) and exe.lower().endswith(('.exe', '.dll', '.sys')):
                imports = scan_pe_for_keys(exe)
                if imports:
                    flags.append("imports_key_api")
            procs.append({
                "pid": info['pid'],
                "name": name,
                "exe": exe,
                "cmdline": cmd,
                "flags": ", ".join(flags),
                "imports": ", ".join(sorted(imports))
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return procs

def check_registry_run_keys():
    suspicious = []
    roots = [(winreg.HKEY_CURRENT_USER, r"Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
             (winreg.HKEY_LOCAL_MACHINE, r"Software\\Microsoft\\Windows\\CurrentVersion\\Run")]
    for root, sub in roots:
        try:
            key = winreg.OpenKey(root, sub)
        except FileNotFoundError:
            continue
        except PermissionError:
            continue
        try:
            i = 0
            while True:
                name, val, _ = winreg.EnumValue(key, i)
                i += 1
                lower = name.lower() + " " + (val.lower() if isinstance(val, str) else "")
                if any(tok in lower for tok in SUSPICIOUS_NAMES):
                    suspicious.append({"key_name": name, "value": val})
        except OSError:
            pass
    return suspicious

def check_schtasks():
    """Query scheduled tasks and find suspicious-looking tasks."""
    suspicious = []
    try:
        out = subprocess.check_output(["schtasks","/Query","/FO","LIST","/V"], stderr=subprocess.DEVNULL, text=True, encoding='utf-8', errors='ignore')
        current = {}
        for line in out.splitlines():
            if "TaskName:" in line:
                current = {"TaskName": line.split(":",1)[1].strip()}
            if "Task To Run:" in line:
                current["TaskToRun"] = line.split(":",1)[1].strip()
                lower = current["TaskToRun"].lower()
                if any(tok in lower for tok in SUSPICIOUS_NAMES):
                    suspicious.append(current.copy())
    except Exception:
        pass
    return suspicious

def pretty_print_file_results(file_results):
    if not file_results:
        print("No suspicious files found in scanned paths.")
        return
    rows = []
    for r in file_results:
        rows.append([r['path'], r['name_flag'], r['suspicious_imports'], r['size']])
    print(tabulate(rows, headers=["Path","NameFlag","SuspiciousImports","Size"], tablefmt="grid"))

def pretty_print_procs(procs):
    rows = []
    for p in procs:
        if p['flags']:
            rows.append([p['pid'], p['name'], p['exe'], p['flags'], p['imports']])
    if rows:
        print("\nSuspicious Running Processes:")
        print(tabulate(rows, headers=["PID","Name","Exe","Flags","Imports"], tablefmt="grid"))
    else:
        print("\nNo suspicious running processes detected by heuristics.")

def main():
    parser = argparse.ArgumentParser(description="Simple Keylogger Detector (heuristics)")
    parser.add_argument("--paths", nargs="*", help="Paths to scan", default=[])
    args = parser.parse_args()
    paths = args.paths if args.paths else [os.getcwd()]

    print("Scanning paths:", paths)
    file_results = scan_files(paths)
    pretty_print_file_results(file_results)

    procs = enumerate_processes()
    pretty_print_procs(procs)

    print("\\nChecking autorun registry keys...")
    reg = check_registry_run_keys()
    if reg:
        print(tabulate([[r['key_name'], r['value']] for r in reg], headers=["Key","Value"], tablefmt="grid"))
    else:
        print("No suspicious Run registry entries detected.")

    print("\\nChecking scheduled tasks for suspicious entries...")
    tasks = check_schtasks()
    if tasks:
        print(tabulate([[t.get('TaskName'), t.get('TaskToRun')] for t in tasks], headers=["TaskName","TaskToRun"], tablefmt="grid"))
    else:
        print("No suspicious scheduled tasks detected.")

if __name__ == "__main__":
    main()
