#!/usr/bin/env python3
"""
##############################################
## Freeworld - Allergic to aluminum baby   ##
## OSCP Command DB - Config Files Patch    ##
##############################################

Adds searchable config/ini/credential file reference entries for:
  - Windows config files (.ini, .conf, .xml, .config, unattend, etc.)
  - Linux config files (/etc, app configs, dot files, etc.)
  - Common app configs (web stacks, mail, DB, cloud)
  - Search one-liners to find and grep all of the above

Tagging strategy:
  'oscp windows config'   -> all Windows config entries
  'oscp linux config'     -> all Linux config entries
  'oscp unattend'         -> unattended install files specifically
  'oscp iis config'       -> IIS-specific configs
  'oscp web config'       -> all web stack configs
  'oscp config grep'      -> all grep/findstr one-liners
  'oscp config creds'     -> anything likely to contain passwords

Usage:
    python3 add_config_files.py
"""

import sqlite3
import os
import sys

DB_PATH = os.path.expanduser("~/.oscp_commands.db")

# (tool, description, command, category, tags)
COMMANDS = [

    # ============================================================
    # WINDOWS — Unattended / Sysprep / WDS (highest value first)
    # ============================================================
    ("config", "Unattend.xml — admin password from Windows setup (base64 or cleartext)",
     "C:\\Windows\\Panther\\Unattend.xml",
     "configs", "config,windows,unattend,xml,creds,setup,windows-config"),

    ("config", "Unattended.xml — alternate location",
     "C:\\Windows\\Panther\\Unattended.xml",
     "configs", "config,windows,unattend,xml,creds,setup,windows-config"),

    ("config", "Sysprep unattend.xml — admin password",
     "C:\\Windows\\System32\\sysprep\\unattend.xml",
     "configs", "config,windows,sysprep,unattend,xml,creds,windows-config"),

    ("config", "Sysprep sysprep.xml",
     "C:\\Windows\\System32\\sysprep\\sysprep.xml",
     "configs", "config,windows,sysprep,xml,creds,windows-config"),

    ("config", "WDS answer file at root",
     "C:\\autounattend.xml",
     "configs", "config,windows,wds,unattend,xml,creds,windows-config"),

    ("config", "PowerShell: find all unattend files on disk",
     "Get-ChildItem -Recurse -ErrorAction SilentlyContinue -Include 'Unattend*','autounattend*','sysprep*' C:\\ | Select FullName",
     "configs", "config,windows,unattend,find,powershell,windows-config"),

    ("config", "CMD: findstr for password in all unattend XMLs",
     "findstr /si \"password\" C:\\Windows\\Panther\\*.xml C:\\Windows\\System32\\sysprep\\*.xml C:\\autounattend.xml 2>nul",
     "configs", "config,windows,unattend,grep,findstr,creds,windows-config,config-grep"),

    # ============================================================
    # WINDOWS — IIS / ASP.NET Config
    # ============================================================
    ("config", "IIS web.config — connection strings, machineKey, app settings",
     "C:\\inetpub\\wwwroot\\web.config",
     "configs", "config,windows,iis,web.config,connstring,machinekey,creds,iis-config,windows-config"),

    ("config", "IIS applicationHost.config — app pool identities, site bindings",
     "C:\\Windows\\System32\\inetsrv\\config\\applicationHost.config",
     "configs", "config,windows,iis,applicationhost,apppool,creds,iis-config,windows-config"),

    ("config", "ASP.NET appsettings.json — .NET Core DB/SMTP/API creds",
     "C:\\inetpub\\wwwroot\\appsettings.json",
     "configs", "config,windows,iis,aspnet,appsettings,json,creds,iis-config,windows-config"),

    ("config", "ASP.NET appsettings.Production.json — production secrets",
     "C:\\inetpub\\wwwroot\\appsettings.Production.json",
     "configs", "config,windows,iis,aspnet,production,json,creds,iis-config,windows-config"),

    ("config", "ASP.NET secrets.json — .NET user secrets store",
     "%APPDATA%\\Microsoft\\UserSecrets\\<GUID>\\secrets.json",
     "configs", "config,windows,iis,aspnet,secrets,json,creds,iis-config,windows-config"),

    ("config", "Classic ASP Global.asax — may contain DB connection strings",
     "C:\\inetpub\\wwwroot\\Global.asax",
     "configs", "config,windows,iis,asp,global,asax,creds,iis-config,windows-config"),

    ("config", "Azure publish settings — contains management certificates",
     "%USERPROFILE%\\*.publishsettings",
     "configs", "config,windows,azure,publish,creds,iis-config,windows-config"),

    ("config", "PowerShell: find ALL web.config files on disk",
     "Get-ChildItem -Recurse -ErrorAction SilentlyContinue -Filter 'web.config' C:\\ | Select FullName",
     "configs", "config,windows,iis,web.config,find,powershell,windows-config"),

    ("config", "CMD: findstr for password/connstring in all web.config files",
     "findstr /si \"password\\|connectionString\\|machineKey\\|apikey\\|secret\" C:\\inetpub\\*.config C:\\inetpub\\**\\*.config 2>nul",
     "configs", "config,windows,iis,findstr,grep,creds,windows-config,config-grep"),

    # ============================================================
    # WINDOWS — Group Policy / SYSVOL
    # ============================================================
    ("config", "GPP Groups.xml — cPassword (decryptable with gpp-decrypt)",
     "\\\\<DC>\\SYSVOL\\<DOMAIN>\\Policies\\**\\Groups.xml",
     "configs", "config,windows,gpp,cpassword,groups,xml,creds,ad,windows-config"),

    ("config", "GPP ScheduledTasks.xml — task credentials",
     "\\\\<DC>\\SYSVOL\\<DOMAIN>\\Policies\\**\\ScheduledTasks.xml",
     "configs", "config,windows,gpp,cpassword,schtasks,xml,creds,ad,windows-config"),

    ("config", "GPP Services.xml — service account credentials",
     "\\\\<DC>\\SYSVOL\\<DOMAIN>\\Policies\\**\\Services.xml",
     "configs", "config,windows,gpp,cpassword,services,xml,creds,ad,windows-config"),

    ("config", "GPP DataSources.xml — ODBC DSN credentials",
     "\\\\<DC>\\SYSVOL\\<DOMAIN>\\Policies\\**\\DataSources.xml",
     "configs", "config,windows,gpp,cpassword,datasources,xml,creds,ad,windows-config"),

    ("config", "GPP Drives.xml — mapped drive passwords",
     "\\\\<DC>\\SYSVOL\\<DOMAIN>\\Policies\\**\\Drives.xml",
     "configs", "config,windows,gpp,cpassword,drives,xml,creds,ad,windows-config"),

    ("config", "CMD: findstr cPassword across all SYSVOL XMLs",
     "findstr /si \"cPassword\" \\\\<DC>\\SYSVOL\\*.xml",
     "configs", "config,windows,gpp,cpassword,findstr,sysvol,windows-config,config-grep"),

    ("config", "Decrypt GPP cPassword on Kali",
     "gpp-decrypt <CPASSWORD_VALUE>",
     "configs", "config,windows,gpp,decrypt,kali,cpassword,windows-config"),

    # ============================================================
    # WINDOWS — Registry Credential Locations
    # ============================================================
    ("config", "Registry: Winlogon autologon DefaultPassword",
     "reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\" /v DefaultPassword",
     "configs", "config,windows,registry,winlogon,autologon,password,creds,windows-config"),

    ("config", "Registry: Winlogon DefaultUsername",
     "reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\" /v DefaultUserName",
     "configs", "config,windows,registry,winlogon,autologon,username,creds,windows-config"),

    ("config", "Registry: AlwaysInstallElevated (both keys needed = privesc)",
     "reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated & reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated",
     "configs", "config,windows,registry,msi,elevated,privesc,windows-config"),

    ("config", "Registry: VNC password (TightVNC / UltraVNC)",
     "reg query HKCU\\Software\\TightVNC\\Server /v Password & reg query HKLM\\SOFTWARE\\RealVNC\\WinVNC4 /v Password",
     "configs", "config,windows,registry,vnc,password,creds,windows-config"),

    ("config", "Registry: PuTTY saved sessions (hostnames + usernames)",
     "reg query HKCU\\Software\\SimonTatham\\PuTTY\\Sessions /s",
     "configs", "config,windows,registry,putty,sessions,creds,windows-config"),

    ("config", "Registry: SNMP community strings",
     "reg query HKLM\\SYSTEM\\CurrentControlSet\\Services\\SNMP\\Parameters\\ValidCommunities",
     "configs", "config,windows,registry,snmp,community,creds,windows-config"),

    ("config", "Registry: MSSQL server instance names",
     "reg query HKLM\\SOFTWARE\\Microsoft\\Microsoft SQL Server\\Instance Names\\SQL",
     "configs", "config,windows,registry,mssql,instances,enum,windows-config"),

    ("config", "Registry: PowerShell: search all hives for 'password'",
     "reg query HKLM /f password /t REG_SZ /s 2>nul; reg query HKCU /f password /t REG_SZ /s 2>nul",
     "configs", "config,windows,registry,search,password,creds,windows-config,config-grep"),

    # ============================================================
    # WINDOWS — User Profile / App Credential Files
    # ============================================================
    ("config", "PowerShell history — commands typed including inline creds",
     "%APPDATA%\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt",
     "configs", "config,windows,powershell,history,creds,user,windows-config"),

    ("config", "FileZilla sitemanager.xml — FTP saved credentials (plaintext)",
     "%APPDATA%\\FileZilla\\sitemanager.xml",
     "configs", "config,windows,filezilla,ftp,xml,creds,user,windows-config"),

    ("config", "FileZilla recentservers.xml — recent FTP hosts",
     "%APPDATA%\\FileZilla\\recentservers.xml",
     "configs", "config,windows,filezilla,ftp,xml,creds,user,windows-config"),

    ("config", "WinSCP .ini — saved session passwords (encrypted but crackable)",
     "%APPDATA%\\WinSCP.ini",
     "configs", "config,windows,winscp,ini,sftp,creds,user,windows-config"),

    ("config", "WinSCP registry sessions",
     "reg query HKCU\\Software\\Martin Prikryl\\WinSCP 2\\Sessions /s",
     "configs", "config,windows,winscp,registry,sftp,creds,windows-config"),

    ("config", "MobaXterm — saved sessions and passwords",
     "%APPDATA%\\MobaXterm\\MobaXterm.ini",
     "configs", "config,windows,mobaxterm,ini,sessions,creds,user,windows-config"),

    ("config", "AWS CLI credentials file",
     "%USERPROFILE%\\.aws\\credentials",
     "configs", "config,windows,aws,credentials,keys,cloud,user,windows-config"),

    ("config", "AWS CLI config file",
     "%USERPROFILE%\\.aws\\config",
     "configs", "config,windows,aws,config,cloud,user,windows-config"),

    ("config", "Git config — may contain PAT tokens in remote URL",
     "%USERPROFILE%\\.gitconfig",
     "configs", "config,windows,git,token,creds,user,windows-config"),

    ("config", "Git credentials store — plaintext tokens",
     "%USERPROFILE%\\.git-credentials",
     "configs", "config,windows,git,credentials,token,plaintext,creds,user,windows-config"),

    ("config", "SSH user private key",
     "%USERPROFILE%\\.ssh\\id_rsa",
     "configs", "config,windows,ssh,key,private,creds,user,windows-config"),

    ("config", "SSH known_hosts — reveals internal host fingerprints",
     "%USERPROFILE%\\.ssh\\known_hosts",
     "configs", "config,windows,ssh,known,hosts,recon,user,windows-config"),

    ("config", "Chrome Login Data — SQLite DB with saved passwords",
     "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Login Data",
     "configs", "config,windows,chrome,browser,passwords,sqlite,creds,user,windows-config"),

    ("config", "Firefox logins.json — encrypted saved passwords",
     "%APPDATA%\\Mozilla\\Firefox\\Profiles\\*.default-release\\logins.json",
     "configs", "config,windows,firefox,browser,passwords,json,creds,user,windows-config"),

    ("config", "DPAPI Credential blobs (decrypt with mimikatz)",
     "%APPDATA%\\Microsoft\\Credentials\\* | %LOCALAPPDATA%\\Microsoft\\Credentials\\*",
     "configs", "config,windows,dpapi,credentials,blobs,creds,user,windows-config"),

    # ============================================================
    # WINDOWS — Service / Software Config Files
    # ============================================================
    ("config", "XAMPP config — MySQL root password",
     "C:\\xampp\\mysql\\bin\\my.ini",
     "configs", "config,windows,xampp,mysql,ini,creds,windows-config"),

    ("config", "XAMPP Apache config",
     "C:\\xampp\\apache\\conf\\httpd.conf",
     "configs", "config,windows,xampp,apache,conf,windows-config"),

    ("config", "XAMPP PHP config (may have DB creds)",
     "C:\\xampp\\php\\php.ini",
     "configs", "config,windows,xampp,php,ini,creds,windows-config"),

    ("config", "OpenSSH for Windows sshd_config",
     "C:\\ProgramData\\ssh\\sshd_config",
     "configs", "config,windows,ssh,sshd,conf,windows-config"),

    ("config", "Jenkins secrets — master.key + credentials.xml",
     "C:\\Program Files\\Jenkins\\secrets\\master.key | C:\\Program Files\\Jenkins\\credentials.xml",
     "configs", "config,windows,jenkins,secrets,key,xml,creds,windows-config"),

    ("config", "Tomcat users.xml — manager credentials",
     "C:\\Program Files\\Apache Software Foundation\\Tomcat*\\conf\\tomcat-users.xml",
     "configs", "config,windows,tomcat,users,xml,creds,windows-config"),

    ("config", "MySQL my.ini — Windows MySQL config",
     "C:\\ProgramData\\MySQL\\MySQL Server*\\my.ini",
     "configs", "config,windows,mysql,ini,creds,windows-config"),

    # ============================================================
    # WINDOWS — Sweep One-Liners
    # ============================================================
    ("config", "CMD: recursive findstr for 'password' in common file types",
     "findstr /si \"password\" C:\\*.xml C:\\*.ini C:\\*.txt C:\\*.config C:\\*.conf C:\\*.cfg C:\\*.json 2>nul",
     "configs", "config,windows,findstr,grep,password,creds,sweep,windows-config,config-grep"),

    ("config", "PowerShell: recurse all drives for credential strings",
     "Get-ChildItem C:\\ -Recurse -ErrorAction SilentlyContinue -Include *.xml,*.ini,*.conf,*.config,*.cfg,*.json,*.txt,*.env | Select-String -Pattern 'password|passwd|secret|api_key|token|credential' | Select Path,LineNumber,Line | Out-File C:\\temp\\creds_found.txt",
     "configs", "config,windows,powershell,grep,creds,sweep,windows-config,config-grep"),

    ("config", "PowerShell: find all .ini files on disk",
     "Get-ChildItem C:\\ -Recurse -ErrorAction SilentlyContinue -Filter *.ini | Select FullName",
     "configs", "config,windows,ini,find,powershell,windows-config"),

    ("config", "PowerShell: find all .conf and .config files",
     "Get-ChildItem C:\\ -Recurse -ErrorAction SilentlyContinue -Include *.conf,*.config | Select FullName",
     "configs", "config,windows,conf,config,find,powershell,windows-config"),

    ("config", "PowerShell: find all .env files on disk",
     "Get-ChildItem C:\\ -Recurse -ErrorAction SilentlyContinue -Filter .env | Select FullName",
     "configs", "config,windows,env,find,powershell,windows-config"),

    ("config", "PowerShell: find backup config files (.bak .old .orig)",
     "Get-ChildItem C:\\ -Recurse -ErrorAction SilentlyContinue -Include *.bak,*.old,*.orig,*backup* | Select FullName",
     "configs", "config,windows,backup,bak,old,find,windows-config"),

    # ============================================================
    # LINUX — /etc Config Files
    # ============================================================
    ("config", "/etc/passwd — user accounts + shells (world readable)",
     "/etc/passwd",
     "configs", "config,linux,passwd,users,shells,linux-config"),

    ("config", "/etc/shadow — hashed passwords (needs root)",
     "/etc/shadow",
     "configs", "config,linux,shadow,hashes,creds,linux-config"),

    ("config", "/etc/sudoers — sudo rules (all:all = instant root)",
     "/etc/sudoers",
     "configs", "config,linux,sudoers,sudo,privesc,linux-config"),

    ("config", "/etc/sudoers.d/* — per-package sudo overrides",
     "/etc/sudoers.d/*",
     "configs", "config,linux,sudoers,sudo,privesc,linux-config"),

    ("config", "/etc/crontab — system-wide cron jobs (check for writable scripts)",
     "/etc/crontab",
     "configs", "config,linux,cron,crontab,privesc,linux-config"),

    ("config", "/etc/cron.d/* — drop-in cron files",
     "/etc/cron.d/*",
     "configs", "config,linux,cron,privesc,linux-config"),

    ("config", "/etc/hosts — internal hostname mappings",
     "/etc/hosts",
     "configs", "config,linux,hosts,network,recon,linux-config"),

    ("config", "/etc/resolv.conf — DNS servers (pivot recon)",
     "/etc/resolv.conf",
     "configs", "config,linux,dns,resolv,network,recon,linux-config"),

    ("config", "/etc/fstab — mounts including NFS shares (no_root_squash = privesc)",
     "/etc/fstab",
     "configs", "config,linux,fstab,nfs,mounts,privesc,linux-config"),

    ("config", "/etc/exports — NFS exported shares (check no_root_squash)",
     "/etc/exports",
     "configs", "config,linux,nfs,exports,privesc,linux-config"),

    ("config", "/etc/environment — system-wide env vars (check for API keys)",
     "/etc/environment",
     "configs", "config,linux,environment,env,keys,linux-config"),

    ("config", "/etc/profile and /etc/profile.d/* — login env vars",
     "/etc/profile | /etc/profile.d/*.sh",
     "configs", "config,linux,profile,env,login,linux-config"),

    ("config", "/etc/ssh/sshd_config — SSH config (PermitRootLogin, key paths, auth methods)",
     "/etc/ssh/sshd_config",
     "configs", "config,linux,ssh,sshd,config,linux-config"),

    ("config", "/etc/ldap/ldap.conf — LDAP client config (may have bind creds)",
     "/etc/ldap/ldap.conf",
     "configs", "config,linux,ldap,bind,creds,linux-config"),

    # ============================================================
    # LINUX — Web Stack Config Files
    # ============================================================
    ("config", "Apache httpd.conf — main config (auth, paths, modules)",
     "/etc/apache2/apache2.conf | /etc/httpd/conf/httpd.conf",
     "configs", "config,linux,apache,httpd,conf,web,linux-config"),

    ("config", "Apache sites-enabled — vhost configs (may have auth directives)",
     "/etc/apache2/sites-enabled/*.conf",
     "configs", "config,linux,apache,vhost,conf,web,linux-config"),

    ("config", "Apache .htpasswd — HTTP basic auth credentials",
     "find / -name '.htpasswd' 2>/dev/null",
     "configs", "config,linux,apache,htpasswd,creds,web,linux-config"),

    ("config", "Apache .htaccess — per-directory config (may reference .htpasswd)",
     "find /var/www -name '.htaccess' 2>/dev/null",
     "configs", "config,linux,apache,htaccess,web,linux-config"),

    ("config", "Nginx nginx.conf — main config",
     "/etc/nginx/nginx.conf",
     "configs", "config,linux,nginx,conf,web,linux-config"),

    ("config", "Nginx sites-enabled — vhost configs",
     "/etc/nginx/sites-enabled/*",
     "configs", "config,linux,nginx,vhost,web,linux-config"),

    ("config", "PHP php.ini — PHP config (may expose DB creds, open_basedir)",
     "/etc/php/*/cli/php.ini | /etc/php/*/apache2/php.ini",
     "configs", "config,linux,php,ini,web,linux-config"),

    # ============================================================
    # LINUX — Application Config Files
    # ============================================================
    ("config", "WordPress wp-config.php — DB user/pass + secret keys",
     "/var/www/html/wp-config.php | find /var/www -name 'wp-config.php' 2>/dev/null",
     "configs", "config,linux,wordpress,php,web,creds,linux-config"),

    ("config", "Laravel .env — DB, mail, API keys, APP_KEY",
     "/var/www/html/.env | find /var/www -name '.env' 2>/dev/null",
     "configs", "config,linux,laravel,env,web,creds,linux-config"),

    ("config", "Django settings.py — SECRET_KEY, DB creds, allowed hosts",
     "find / -name 'settings.py' 2>/dev/null | grep -v '__pycache__'",
     "configs", "config,linux,django,python,web,creds,linux-config"),

    ("config", "MySQL my.cnf — root password, socket, bind address",
     "/etc/mysql/my.cnf | /etc/mysql/mysql.conf.d/mysqld.cnf",
     "configs", "config,linux,mysql,mycnf,creds,linux-config"),

    ("config", "~/.my.cnf — user-level MySQL stored credentials",
     "~/.my.cnf | /root/.my.cnf | /home/*/.my.cnf",
     "configs", "config,linux,mysql,mycnf,creds,user,linux-config"),

    ("config", "PostgreSQL pg_hba.conf — auth methods (trust = no password needed)",
     "/etc/postgresql/*/main/pg_hba.conf",
     "configs", "config,linux,postgresql,pghba,auth,creds,linux-config"),

    ("config", "~/.pgpass — PostgreSQL stored passwords",
     "~/.pgpass | /root/.pgpass",
     "configs", "config,linux,postgresql,pgpass,creds,user,linux-config"),

    ("config", "Redis redis.conf — requirepass, bind address",
     "/etc/redis/redis.conf",
     "configs", "config,linux,redis,conf,creds,linux-config"),

    ("config", "MongoDB mongod.conf — auth enabled, bind IP",
     "/etc/mongod.conf",
     "configs", "config,linux,mongodb,conf,auth,linux-config"),

    ("config", "Tomcat tomcat-users.xml — manager credentials",
     "/opt/tomcat/conf/tomcat-users.xml | /etc/tomcat*/tomcat-users.xml",
     "configs", "config,linux,tomcat,java,users,xml,creds,linux-config"),

    ("config", "Jenkins credentials.xml — stored job credentials",
     "/var/lib/jenkins/credentials.xml",
     "configs", "config,linux,jenkins,credentials,xml,creds,linux-config"),

    ("config", "Jenkins secrets/master.key — Jenkins encryption key",
     "/var/lib/jenkins/secrets/master.key",
     "configs", "config,linux,jenkins,secrets,key,creds,linux-config"),

    # ============================================================
    # LINUX — User Dot Files
    # ============================================================
    ("config", "~/.bash_history — command history (inline creds very common)",
     "/root/.bash_history | /home/*/.bash_history",
     "configs", "config,linux,bash,history,creds,user,linux-config"),

    ("config", "~/.zsh_history — Zsh command history",
     "/home/*/.zsh_history | /root/.zsh_history",
     "configs", "config,linux,zsh,history,creds,user,linux-config"),

    ("config", "~/.bashrc / ~/.bash_profile — env vars, aliases with creds",
     "/home/*/.bashrc | /home/*/.bash_profile | /root/.bashrc",
     "configs", "config,linux,bashrc,env,creds,user,linux-config"),

    ("config", "~/.netrc — FTP/curl/wget stored credentials",
     "/home/*/.netrc | /root/.netrc",
     "configs", "config,linux,netrc,ftp,curl,creds,user,linux-config"),

    ("config", "~/.ssh/id_rsa — user SSH private key",
     "/home/*/.ssh/id_rsa | /root/.ssh/id_rsa",
     "configs", "config,linux,ssh,key,private,creds,user,linux-config"),

    ("config", "~/.ssh/authorized_keys — trusted public keys (who can log in)",
     "/home/*/.ssh/authorized_keys | /root/.ssh/authorized_keys",
     "configs", "config,linux,ssh,authorized,keys,user,linux-config"),

    ("config", "~/.aws/credentials — AWS access keys",
     "/home/*/.aws/credentials | /root/.aws/credentials",
     "configs", "config,linux,aws,credentials,keys,cloud,user,linux-config"),

    ("config", "~/.git-credentials — Git stored tokens (plaintext)",
     "/home/*/.git-credentials | /root/.git-credentials",
     "configs", "config,linux,git,credentials,token,plaintext,creds,user,linux-config"),

    ("config", "~/.docker/config.json — Docker registry auth tokens",
     "/home/*/.docker/config.json | /root/.docker/config.json",
     "configs", "config,linux,docker,registry,auth,token,creds,user,linux-config"),

    ("config", "~/.kube/config — Kubernetes cluster credentials",
     "/home/*/.kube/config | /root/.kube/config",
     "configs", "config,linux,kubernetes,kube,config,creds,user,linux-config"),

    # ============================================================
    # LINUX — Process / Runtime Credential Leaks
    # ============================================================
    ("config", "/proc/*/environ — running process environment variables",
     "cat /proc/*/environ 2>/dev/null | tr '\\0' '\\n' | grep -iE 'pass|key|token|secret'",
     "configs", "config,linux,proc,environ,env,creds,linux-config"),

    ("config", "/proc/*/cmdline — process arguments (DB connection strings common)",
     "cat /proc/*/cmdline 2>/dev/null | tr '\\0' ' ' | grep -iE 'pass|password|secret|key'",
     "configs", "config,linux,proc,cmdline,args,creds,linux-config"),

    # ============================================================
    # LINUX — Sweep One-Liners
    # ============================================================
    ("config", "Find ALL config/ini/env files readable by current user",
     "find / -readable \\( -name '*.conf' -o -name '*.config' -o -name '*.cfg' -o -name '*.ini' -o -name '*.env' -o -name '*.properties' -o -name '*.yml' -o -name '*.yaml' \\) 2>/dev/null | grep -v proc",
     "configs", "config,linux,find,all,readable,sweep,linux-config,config-grep"),

    ("config", "Grep config files for passwords (broad sweep)",
     "grep -rni 'password\\|passwd\\|pass\\s*=\\|secret\\|api_key\\|token\\|credential' /etc /opt /var/www /home /root 2>/dev/null --include='*.conf' --include='*.config' --include='*.cfg' --include='*.ini' --include='*.env' --include='*.php' --include='*.py' --include='*.rb' --include='*.xml' --include='*.json' --include='*.yml'",
     "configs", "config,linux,grep,sweep,password,creds,all,linux-config,config-grep"),

    ("config", "Find backup config files on Linux",
     "find / -name '*.bak' -o -name '*.old' -o -name '*.orig' -o -name '*.backup' -o -name '*~' 2>/dev/null | grep -v proc",
     "configs", "config,linux,backup,bak,old,find,linux-config"),

    ("config", "Find world-readable .env files",
     "find / -name '.env' -readable 2>/dev/null",
     "configs", "config,linux,env,find,readable,linux-config"),

    ("config", "Find .xml files that may contain credentials",
     "find / -name '*.xml' -readable 2>/dev/null | grep -v proc | head -50",
     "configs", "config,linux,xml,find,creds,linux-config"),

    ("config", "Find Java .properties files (often DB/API creds)",
     "find / -name '*.properties' -readable 2>/dev/null | grep -v proc",
     "configs", "config,linux,properties,java,creds,linux-config,config-grep"),

    ("config", "Find YAML config files (Docker Compose, k8s, app configs)",
     "find / -name '*.yml' -o -name '*.yaml' 2>/dev/null | grep -v proc | grep -v '/usr/share'",
     "configs", "config,linux,yaml,yml,find,docker,kubernetes,linux-config"),

    ("config", "Grep all shell history files for inline credentials",
     "find /home /root -name '*_history' -readable 2>/dev/null | xargs grep -iE 'password|passwd|secret|key|token|curl.*-u|mysql.*-p|psql.*-W' 2>/dev/null",
     "configs", "config,linux,history,grep,creds,bash,linux-config,config-grep"),

    # ============================================================
    # PHP — Config Files, INI, and Credential Locations
    # Tagged: php,php-config so 'oscp php config' returns all
    # ============================================================

    # php.ini locations by distro/context
    ("config", "PHP php.ini — Debian/Ubuntu CLI",
     "/etc/php/<VERSION>/cli/php.ini",
     "configs", "config,linux,php,ini,cli,php-config"),

    ("config", "PHP php.ini — Debian/Ubuntu Apache module",
     "/etc/php/<VERSION>/apache2/php.ini",
     "configs", "config,linux,php,ini,apache,php-config"),

    ("config", "PHP php.ini — Debian/Ubuntu FPM",
     "/etc/php/<VERSION>/fpm/php.ini",
     "configs", "config,linux,php,ini,fpm,php-config"),

    ("config", "PHP php.ini — RHEL/CentOS",
     "/etc/php.ini",
     "configs", "config,linux,php,ini,rhel,centos,php-config"),

    ("config", "PHP php.ini — RHEL FPM pool",
     "/etc/php-fpm.d/www.conf",
     "configs", "config,linux,php,fpm,pool,rhel,php-config"),

    ("config", "PHP php.ini — Windows XAMPP",
     "C:\\xampp\\php\\php.ini",
     "configs", "config,windows,php,ini,xampp,php-config"),

    ("config", "PHP php.ini — Windows standalone install",
     "C:\\PHP\\php.ini",
     "configs", "config,windows,php,ini,php-config"),

    ("config", "PHP php.ini — find all php.ini files on system",
     "find / -name 'php.ini' 2>/dev/null",
     "configs", "config,linux,php,ini,find,php-config"),

    # PHP key settings to look for in php.ini
    ("config", "PHP php.ini — check allow_url_fopen (enables remote file include)",
     "grep -i 'allow_url_fopen\\|allow_url_include\\|disable_functions\\|open_basedir' /etc/php/*/cli/php.ini 2>/dev/null",
     "configs", "config,linux,php,ini,lfi,rfi,security,php-config"),

    ("config", "PHP php.ini — check display_errors (leaks paths + stack traces)",
     "grep -i 'display_errors\\|error_reporting\\|error_log\\|log_errors' /etc/php/*/apache2/php.ini 2>/dev/null",
     "configs", "config,linux,php,ini,errors,paths,php-config"),

    ("config", "PHP php.ini — check session settings (session.save_path for hijack)",
     "grep -i 'session.save_path\\|session.name\\|session.cookie' /etc/php/*/apache2/php.ini 2>/dev/null",
     "configs", "config,linux,php,ini,session,cookie,php-config"),

    ("config", "PHP php.ini — check upload settings (upload_tmp_dir, file_uploads)",
     "grep -i 'file_uploads\\|upload_tmp_dir\\|upload_max_filesize\\|post_max_size' /etc/php/*/cli/php.ini 2>/dev/null",
     "configs", "config,linux,php,ini,upload,file,php-config"),

    # PHP-FPM pool configs
    ("config", "PHP-FPM www.conf — pool config (user/group FPM runs as)",
     "/etc/php/<VERSION>/fpm/pool.d/www.conf",
     "configs", "config,linux,php,fpm,pool,user,group,php-config"),

    ("config", "PHP-FPM — find all pool config files",
     "find /etc/php -name '*.conf' 2>/dev/null | grep -i fpm",
     "configs", "config,linux,php,fpm,pool,find,php-config"),

    ("config", "PHP-FPM www.conf — check listen socket and user (privesc path)",
     "grep -E 'listen|user|group|pm\\.' /etc/php/*/fpm/pool.d/www.conf 2>/dev/null",
     "configs", "config,linux,php,fpm,listen,socket,privesc,php-config"),

    # PHP app config files
    ("config", "PHP — WordPress wp-config.php (DB creds + secret keys + table prefix)",
     "find / -name 'wp-config.php' 2>/dev/null",
     "configs", "config,linux,php,wordpress,wp-config,db,creds,php-config"),

    ("config", "PHP — WordPress wp-config.php key values to extract",
     "grep -E \"DB_NAME|DB_USER|DB_PASSWORD|DB_HOST|AUTH_KEY|SECURE_AUTH_KEY|table_prefix\" /var/www/html/wp-config.php 2>/dev/null",
     "configs", "config,linux,php,wordpress,wp-config,grep,creds,php-config"),

    ("config", "PHP — Joomla configuration.php (DB creds + secret)",
     "find / -name 'configuration.php' 2>/dev/null",
     "configs", "config,linux,php,joomla,configuration,db,creds,php-config"),

    ("config", "PHP — Joomla configuration.php key values",
     "grep -E \"\\$user|\\$password|\\$db|\\$secret|\\$host\" /var/www/html/configuration.php 2>/dev/null",
     "configs", "config,linux,php,joomla,grep,creds,php-config"),

    ("config", "PHP — Drupal sites/default/settings.php (DB creds)",
     "find / -path '*/sites/default/settings.php' 2>/dev/null",
     "configs", "config,linux,php,drupal,settings,db,creds,php-config"),

    ("config", "PHP — Laravel .env (APP_KEY, DB, mail, S3, API keys)",
     "find / -name '.env' -readable 2>/dev/null | xargs grep -l 'APP_KEY\\|DB_PASSWORD' 2>/dev/null",
     "configs", "config,linux,php,laravel,env,appkey,db,creds,php-config"),

    ("config", "PHP — Laravel config/database.php (DB connection array)",
     "find / -path '*/config/database.php' 2>/dev/null",
     "configs", "config,linux,php,laravel,database,config,creds,php-config"),

    ("config", "PHP — CodeIgniter application/config/database.php",
     "find / -path '*/application/config/database.php' 2>/dev/null",
     "configs", "config,linux,php,codeigniter,database,creds,php-config"),

    ("config", "PHP — CodeIgniter application/config/config.php (encryption key)",
     "find / -path '*/application/config/config.php' 2>/dev/null",
     "configs", "config,linux,php,codeigniter,config,encryption,key,php-config"),

    ("config", "PHP — generic config.php / db.php / database.php anywhere in webroot",
     "find /var/www -name 'config.php' -o -name 'db.php' -o -name 'database.php' -o -name 'db_config.php' -o -name 'connect.php' 2>/dev/null",
     "configs", "config,linux,php,generic,config,db,creds,php-config"),

    ("config", "PHP — find all PHP files with hardcoded DB credentials",
     "grep -rn \"\\$db_pass\\|\\$dbpass\\|\\$password\\|\\$db_password\\|mysql_connect\\|mysqli_connect\\|PDO(\" /var/www 2>/dev/null | grep -v '.min.js'",
     "configs", "config,linux,php,grep,hardcoded,db,creds,php-config,config-grep"),

    ("config", "PHP — session files (may contain serialized auth data)",
     "ls -la /var/lib/php/sessions/ 2>/dev/null | head -20",
     "configs", "config,linux,php,sessions,files,auth,php-config"),

    ("config", "PHP — session save path (find from php.ini)",
     "grep -r 'session.save_path' /etc/php 2>/dev/null",
     "configs", "config,linux,php,session,save,path,php-config"),

    ("config", "PHP — error log location (find from php.ini)",
     "grep -r 'error_log' /etc/php 2>/dev/null | grep -v ';'",
     "configs", "config,linux,php,error,log,path,php-config"),

    ("config", "PHP — find all PHP error logs on disk",
     "find / -name 'php_errors.log' -o -name 'php-error.log' -o -name 'php_error.log' 2>/dev/null",
     "configs", "config,linux,php,error,log,find,php-config"),

    ("config", "PHP — phpinfo() output page (full config dump if accessible)",
     "curl -s http://<IP>/phpinfo.php | grep -iE 'DB_|password|secret|key|_PASS'",
     "configs", "config,linux,php,phpinfo,dump,creds,php-config"),

    ("config", "PHP — find phpinfo pages in webroot",
     "find /var/www -name 'phpinfo.php' -o -name 'info.php' -o -name 'test.php' 2>/dev/null",
     "configs", "config,linux,php,phpinfo,find,php-config"),

    ("config", "PHP — composer.json (dependency versions for known CVEs)",
     "find /var/www -name 'composer.json' 2>/dev/null",
     "configs", "config,linux,php,composer,json,versions,cve,php-config"),

    ("config", "PHP — composer.lock (exact installed versions for CVE matching)",
     "find /var/www -name 'composer.lock' 2>/dev/null",
     "configs", "config,linux,php,composer,lock,versions,cve,php-config"),

    # ============================================================
    # Nginx — Config Files and Credential Locations
    # Tagged: nginx,nginx-config so 'oscp nginx config' returns all
    # ============================================================

    # Main config files
    ("config", "Nginx — main config file",
     "/etc/nginx/nginx.conf",
     "configs", "config,linux,nginx,conf,main,nginx-config"),

    ("config", "Nginx — sites-available directory (all vhost definitions)",
     "/etc/nginx/sites-available/",
     "configs", "config,linux,nginx,sites,available,vhost,nginx-config"),

    ("config", "Nginx — sites-enabled directory (active vhosts symlinked here)",
     "/etc/nginx/sites-enabled/",
     "configs", "config,linux,nginx,sites,enabled,vhost,nginx-config"),

    ("config", "Nginx — conf.d directory (RHEL/CentOS drop-in configs)",
     "/etc/nginx/conf.d/",
     "configs", "config,linux,nginx,conf.d,rhel,centos,nginx-config"),

    ("config", "Nginx — RHEL/CentOS main config location",
     "/etc/nginx/nginx.conf  # RHEL: /usr/share/nginx/html is webroot",
     "configs", "config,linux,nginx,rhel,centos,main,nginx-config"),

    ("config", "Nginx — find ALL nginx config files on system",
     "find /etc/nginx -name '*.conf' 2>/dev/null",
     "configs", "config,linux,nginx,find,all,conf,nginx-config"),

    # Key Nginx directives to look for
    ("config", "Nginx — grep all configs for auth_basic (HTTP basic auth creds file path)",
     "grep -rn 'auth_basic' /etc/nginx/ 2>/dev/null",
     "configs", "config,linux,nginx,auth,basic,htpasswd,creds,nginx-config"),

    ("config", "Nginx — grep all configs for proxy_pass (reveals internal services)",
     "grep -rn 'proxy_pass' /etc/nginx/ 2>/dev/null",
     "configs", "config,linux,nginx,proxy,pass,internal,recon,nginx-config"),

    ("config", "Nginx — grep for fastcgi_pass (PHP-FPM socket/port)",
     "grep -rn 'fastcgi_pass\\|fastcgi_param' /etc/nginx/ 2>/dev/null",
     "configs", "config,linux,nginx,fastcgi,php,fpm,socket,nginx-config"),

    ("config", "Nginx — grep for SSL cert and key paths",
     "grep -rn 'ssl_certificate\\|ssl_certificate_key' /etc/nginx/ 2>/dev/null",
     "configs", "config,linux,nginx,ssl,cert,key,paths,nginx-config"),

    ("config", "Nginx — grep for root directive (webroot locations)",
     "grep -rn 'root ' /etc/nginx/sites-enabled/ /etc/nginx/conf.d/ 2>/dev/null",
     "configs", "config,linux,nginx,root,webroot,paths,nginx-config"),

    ("config", "Nginx — grep for server_name (find all hosted domains/subdomains)",
     "grep -rn 'server_name' /etc/nginx/sites-enabled/ /etc/nginx/conf.d/ 2>/dev/null",
     "configs", "config,linux,nginx,server,name,domains,recon,nginx-config"),

    ("config", "Nginx — grep for upstream blocks (load balancer backend IPs)",
     "grep -rn 'upstream' /etc/nginx/ 2>/dev/null",
     "configs", "config,linux,nginx,upstream,backend,ips,recon,nginx-config"),

    ("config", "Nginx — grep for access_log and error_log paths in vhosts",
     "grep -rn 'access_log\\|error_log' /etc/nginx/sites-enabled/ /etc/nginx/conf.d/ 2>/dev/null",
     "configs", "config,linux,nginx,log,paths,access,error,nginx-config"),

    ("config", "Nginx — grep for add_header (security headers or custom headers leaking info)",
     "grep -rn 'add_header' /etc/nginx/ 2>/dev/null",
     "configs", "config,linux,nginx,headers,security,nginx-config"),

    ("config", "Nginx — grep for allow/deny directives (IP-restricted paths)",
     "grep -rn 'allow\\|deny' /etc/nginx/sites-enabled/ 2>/dev/null",
     "configs", "config,linux,nginx,allow,deny,acl,recon,nginx-config"),

    ("config", "Nginx — grep for rewrite rules (may expose internal redirects)",
     "grep -rn 'rewrite\\|return 30' /etc/nginx/sites-enabled/ 2>/dev/null",
     "configs", "config,linux,nginx,rewrite,redirect,nginx-config"),

    ("config", "Nginx — grep for try_files (reveals URL routing logic)",
     "grep -rn 'try_files' /etc/nginx/sites-enabled/ /etc/nginx/conf.d/ 2>/dev/null",
     "configs", "config,linux,nginx,try,files,routing,nginx-config"),

    ("config", "Nginx — find .htpasswd referenced by auth_basic_user_file",
     "grep -rn 'auth_basic_user_file' /etc/nginx/ 2>/dev/null",
     "configs", "config,linux,nginx,htpasswd,auth,basic,creds,nginx-config"),

    ("config", "Nginx — read .htpasswd file (contains bcrypt/MD5 hashed creds)",
     "cat $(grep -rn 'auth_basic_user_file' /etc/nginx/ 2>/dev/null | awk '{print $NF}' | head -1)",
     "configs", "config,linux,nginx,htpasswd,hashes,creds,nginx-config"),

    # Nginx credential and info leaks
    ("config", "Nginx — check if autoindex is on (directory listing enabled)",
     "grep -rn 'autoindex on' /etc/nginx/ 2>/dev/null",
     "configs", "config,linux,nginx,autoindex,directory,listing,nginx-config"),

    ("config", "Nginx — check for exposed .git via location blocks",
     "grep -rn '\\.git' /etc/nginx/ 2>/dev/null",
     "configs", "config,linux,nginx,git,exposed,nginx-config"),

    ("config", "Nginx — check worker process user (may run as www-data or root)",
     "grep -n 'user ' /etc/nginx/nginx.conf 2>/dev/null | head -5",
     "configs", "config,linux,nginx,user,worker,privesc,nginx-config"),

    ("config", "Nginx — check client_max_body_size (upload size limit)",
     "grep -rn 'client_max_body_size' /etc/nginx/ 2>/dev/null",
     "configs", "config,linux,nginx,upload,size,limit,nginx-config"),

    # Nginx path traversal / misconfig checks
    ("config", "Nginx — check for alias path traversal (alias + no trailing slash = LFI)",
     "grep -rn -A1 'location.*{' /etc/nginx/sites-enabled/ 2>/dev/null | grep -B1 'alias'",
     "configs", "config,linux,nginx,alias,traversal,lfi,nginx-config"),

    ("config", "Nginx — find all location blocks (routing map)",
     "grep -rn 'location ' /etc/nginx/sites-enabled/ /etc/nginx/conf.d/ 2>/dev/null",
     "configs", "config,linux,nginx,location,blocks,routing,nginx-config"),

    # Nginx status / info pages
    ("config", "Nginx — stub_status page (server metrics — check if exposed)",
     "curl -s http://<IP>/nginx_status",
     "configs", "config,linux,nginx,status,metrics,exposed,nginx-config"),

    ("config", "Nginx — check nginx version (for CVE matching)",
     "nginx -v 2>&1",
     "configs", "config,linux,nginx,version,cve,nginx-config"),

    ("config", "Nginx — test config syntax and see effective config",
     "nginx -T 2>/dev/null  # dumps full merged config — huge recon value",
     "configs", "config,linux,nginx,test,dump,effective,recon,nginx-config"),

    # Nginx log locations (cross-reference with logs category)
    ("config", "Nginx — default access log",
     "/var/log/nginx/access.log",
     "configs", "config,linux,nginx,log,access,nginx-config"),

    ("config", "Nginx — default error log",
     "/var/log/nginx/error.log",
     "configs", "config,linux,nginx,log,error,nginx-config"),

    ("config", "Nginx — find all vhost-specific log files",
     "grep -rn 'access_log\\|error_log' /etc/nginx/sites-enabled/ /etc/nginx/conf.d/ 2>/dev/null | awk '{print $NF}' | sort -u",
     "configs", "config,linux,nginx,log,vhost,find,nginx-config"),

    ("config", "Nginx — grep access log for creds in query strings",
     "grep -E 'pass=|password=|token=|secret=|key=|auth=' /var/log/nginx/access.log 2>/dev/null",
     "configs", "config,linux,nginx,log,grep,creds,nginx-config,config-grep"),

    ("config", "Nginx — grep error log for upstream connection failures (reveals internal IPs)",
     "grep -i 'upstream\\|connect()\\|failed\\|no route' /var/log/nginx/error.log 2>/dev/null | tail -30",
     "configs", "config,linux,nginx,error,upstream,internal,ips,nginx-config"),

]


def main():
    if not os.path.exists(DB_PATH):
        print(f"[-] DB not found: {DB_PATH}")
        print("    Run oscp_db_setup.py first.")
        sys.exit(1)

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("PRAGMA table_info(commands)")
    cols = [row[1] for row in cur.fetchall()]
    expected = {"tool", "description", "command", "category", "tags"}
    if not expected.issubset(set(cols)):
        print(f"[-] Schema mismatch. Found: {cols}")
        sys.exit(1)
    print(f"[*] Schema OK")

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
    print("    oscp windows config       # all Windows config files")
    print("    oscp linux config         # all Linux config files")
    print("    oscp unattend             # unattend.xml + sysprep")
    print("    oscp iis config           # web.config, appsettings, etc.")
    print("    oscp gpp cpassword        # GPP Group Policy creds")
    print("    oscp registry password    # registry credential locations")
    print("    oscp config grep          # all sweep one-liners")
    print("    oscp config creds         # anything likely to have passwords")
    print("    oscp linux cron           # cron config + log locations")
    print("    oscp dotfiles             # shell history, .netrc, .aws etc.")
    print("    oscp xampp                # XAMPP config files")
    print("    oscp jenkins              # Jenkins credential files")
    print("    oscp tomcat config        # Tomcat config files")
    print("    oscp php config           # all PHP config + ini files")
    print("    oscp php ini              # php.ini locations by distro")
    print("    oscp php fpm              # PHP-FPM pool configs")
    print("    oscp php wordpress        # wp-config.php grep + find")
    print("    oscp php laravel          # Laravel .env + config/database.php")
    print("    oscp php session          # session files + save path")
    print("    oscp php error            # error log locations + display_errors")
    print("    oscp phpinfo              # phpinfo() pages in webroot")
    print("    oscp nginx config         # all Nginx config files")
    print("    oscp nginx proxy          # proxy_pass — internal service map")
    print("    oscp nginx ssl            # SSL cert + key paths")
    print("    oscp nginx auth           # auth_basic + htpasswd locations")
    print("    oscp nginx log            # access/error log paths per vhost")
    print("    oscp nginx alias          # alias LFI misconfiguration check")
    print("    oscp nginx status         # stub_status + nginx -T config dump")


if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("Config Files Patch — OSCP Command Database")
    print("Freeworld / 1337 Pete")
    print("=" * 60 + "\n")
    main()
