#!/usr/bin/env python3
"""
##############################################
## Freeworld - Allergic to aluminum baby   ##
## OSCP Command Reference Tool             ##
## Usage: oscp <query>                     ##
##############################################
"""
 
import sqlite3
import sys
import os
import argparse
 
DB_PATH = os.path.expanduser("~/.oscp_commands.db")
 
# ── ANSI Colors ──────────────────────────────
R  = "\033[0m"          # reset
BLD= "\033[1m"          # bold
DIM= "\033[2m"          # dim
GRN= "\033[38;5;82m"    # bright green
YLW= "\033[38;5;220m"   # yellow
CYN= "\033[38;5;51m"    # cyan
RED= "\033[38;5;196m"   # red
MGT= "\033[38;5;201m"   # magenta
GRY= "\033[38;5;244m"   # grey
WHT= "\033[38;5;255m"   # white
ORG= "\033[38;5;208m"   # orange
 
CATEGORY_COLORS = {
    "recon":            "\033[38;5;39m",
    "web":              "\033[38;5;82m",
    "passwords":        "\033[38;5;196m",
    "impacket":         "\033[38;5;220m",
    "privesc-linux":    "\033[38;5;208m",
    "privesc-windows":  "\033[38;5;201m",
    "ad":               "\033[38;5;171m",
    "shells":           "\033[38;5;46m",
    "tunneling":        "\033[38;5;51m",
    "misc":             "\033[38;5;244m",
}
 
BANNER = f"""{GRN}{BLD}
  ╔═══════════════════════════════════════════════════╗
  ║   ██████╗ ███████╗ ██████╗██████╗               ║
  ║  ██╔═══██╗██╔════╝██╔════╝██╔══██╗              ║
  ║  ██║   ██║███████╗██║     ██████╔╝              ║
  ║  ██║   ██║╚════██║██║     ██╔═══╝               ║
  ║  ╚██████╔╝███████║╚██████╗██║                   ║
  ║   ╚═════╝ ╚══════╝ ╚═════╝╚═╝                   ║
  ║                                                  ║
  ║  {YLW}Freeworld Command Reference{GRN}                    ║
  ║  {GRY}Allergic to aluminum baby{GRN}                      ║
  ╚═══════════════════════════════════════════════════╝{R}
"""
 
CATEGORIES = [
    ("recon",           "Reconnaissance & Scanning"),
    ("web",             "Web Attacks"),
    ("passwords",       "Password Attacks & Cracking"),
    ("impacket",        "Impacket Suite"),
    ("privesc-linux",   "Linux Privilege Escalation"),
    ("privesc-windows", "Windows Privilege Escalation"),
    ("ad",              "Active Directory"),
    ("shells",          "Shells & File Transfers"),
    ("tunneling",       "Port Forwarding & Tunneling"),
    ("misc",            "Miscellaneous"),
]
 
 
def check_db():
    if not os.path.exists(DB_PATH):
        print(f"{RED}[!] Database not found at {DB_PATH}{R}")
        print(f"{YLW}[*] Run: python3 oscp_db_setup.py{R}")
        sys.exit(1)
 
 
def get_conn():
    return sqlite3.connect(DB_PATH)
 
 
def print_results(rows, highlight=None):
    if not rows:
        print(f"\n{RED}  [!] No results found.{R}\n")
        return
 
    print()
    for row in rows:
        tool, desc, cmd, cat, tags = row
        cat_color = CATEGORY_COLORS.get(cat, GRY)
        cat_label = f"{cat_color}[{cat}]{R}"
 
        # Highlight search term in command and description
        display_cmd = cmd
        display_desc = desc
        if highlight:
            hi = highlight.lower()
            for word in display_cmd.split():
                if hi in word.lower():
                    display_cmd = display_cmd.replace(word, f"{YLW}{BLD}{word}{R}")
                    break
            if hi in display_desc.lower():
                idx = display_desc.lower().find(hi)
                matched = display_desc[idx:idx+len(hi)]
                display_desc = display_desc.replace(matched, f"{YLW}{BLD}{matched}{R}")
 
        print(f"  {GRN}{BLD}┌─{R} {WHT}{BLD}{tool}{R}  {cat_label}  {DIM}{display_desc}{R}")
        print(f"  {GRN}└──▶{R} {CYN}{display_cmd}{R}")
        print()
 
 
def search_all(query):
    """Search tool names, descriptions, commands and tags"""
    conn = get_conn()
    c = conn.cursor()
    q = f"%{query}%"
    c.execute("""
        SELECT tool, description, command, category, tags
        FROM commands
        WHERE tool LIKE ? OR description LIKE ? OR command LIKE ? OR tags LIKE ?
        ORDER BY
            CASE WHEN tool LIKE ? THEN 0
                 WHEN tags LIKE ? THEN 1
                 ELSE 2 END,
            category, tool
    """, (q, q, q, q, q, q))
    rows = c.fetchall()
    conn.close()
    return rows
 
 
def search_category(cat):
    """Return all commands in a category"""
    conn = get_conn()
    c = conn.cursor()
    c.execute("""
        SELECT tool, description, command, category, tags
        FROM commands WHERE category = ?
        ORDER BY tool
    """, (cat,))
    rows = c.fetchall()
    conn.close()
    return rows
 
 
def list_categories():
    print(BANNER)
    print(f"  {BLD}{WHT}Available Categories:{R}\n")
    conn = get_conn()
    c = conn.cursor()
    for cat, label in CATEGORIES:
        c.execute("SELECT COUNT(*) FROM commands WHERE category = ?", (cat,))
        count = c.fetchone()[0]
        col = CATEGORY_COLORS.get(cat, GRY)
        print(f"  {col}{BLD}{cat:<20}{R}  {GRY}{label:<35}{R}  {YLW}({count} commands){R}")
    conn.close()
 
    print(f"\n  {BLD}{WHT}Usage Examples:{R}")
    print(f"  {CYN}oscp impacket{R}              {GRY}# show all impacket commands{R}")
    print(f"  {CYN}oscp kerberos{R}              {GRY}# search for kerberos commands{R}")
    print(f"  {CYN}oscp --cat privesc-linux{R}   {GRY}# show linux privesc category{R}")
    print(f"  {CYN}oscp --cat ad{R}              {GRY}# show all AD commands{R}")
    print(f"  {CYN}oscp --add{R}                 {GRY}# add a new command{R}")
    print(f"  {CYN}oscp --list{R}                {GRY}# list all categories{R}")
    print()
 
 
def add_command():
    """Interactive command addition"""
    print(f"\n  {GRN}{BLD}Add New Command{R}\n")
    tool    = input(f"  {YLW}Tool name:{R} ").strip()
    desc    = input(f"  {YLW}Description:{R} ").strip()
    cmd     = input(f"  {YLW}Command:{R} ").strip()
    print(f"\n  {GRY}Categories: {', '.join([c[0] for c in CATEGORIES])}{R}")
    cat     = input(f"  {YLW}Category:{R} ").strip()
    tags    = input(f"  {YLW}Tags (comma separated):{R} ").strip()
 
    if not all([tool, desc, cmd, cat, tags]):
        print(f"\n  {RED}[!] All fields required.{R}\n")
        return
 
    conn = get_conn()
    c = conn.cursor()
    c.execute("INSERT INTO commands (tool, description, command, category, tags) VALUES (?,?,?,?,?)",
              (tool, desc, cmd, cat, tags))
    conn.commit()
    conn.close()
    print(f"\n  {GRN}[+] Command added successfully!{R}\n")
 
 
def stats():
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM commands")
    total = c.fetchone()[0]
    conn.close()
    print(f"\n  {GRN}[+] Total commands in database: {YLW}{BLD}{total}{R}\n")
 
 
def main():
    check_db()
 
    parser = argparse.ArgumentParser(
        description="OSCP Command Reference Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  oscp impacket              Search for impacket commands
  oscp kerberos              Search anything kerberos related
  oscp reverse shell         Search for reverse shell commands
  oscp --cat privesc-linux   Show all linux privesc commands
  oscp --cat ad              Show all Active Directory commands
  oscp --add                 Add a new command
  oscp --list                List all categories
  oscp --stats               Show database stats
        """
    )
 
    parser.add_argument("query", nargs="*", help="Search term (tool name, keyword, tag)")
    parser.add_argument("--cat", "-c", help="Filter by category")
    parser.add_argument("--add", "-a", action="store_true", help="Add a new command")
    parser.add_argument("--list", "-l", action="store_true", help="List all categories")
    parser.add_argument("--stats", "-s", action="store_true", help="Show database stats")
 
    args = parser.parse_args()
 
    if args.add:
        add_command()
        return
 
    if args.stats:
        stats()
        return
 
    if args.list or (not args.query and not args.cat):
        list_categories()
        return
 
    if args.cat:
        cat = args.cat.lower()
        valid_cats = [c[0] for c in CATEGORIES]
        if cat not in valid_cats:
            print(f"\n{RED}  [!] Unknown category: {cat}{R}")
            print(f"{YLW}  Valid: {', '.join(valid_cats)}{R}\n")
            return
        rows = search_category(cat)
        cat_color = CATEGORY_COLORS.get(cat, GRY)
        label = next((l for c, l in CATEGORIES if c == cat), cat)
        print(f"\n  {cat_color}{BLD}══ {label} ══{R}  {GRY}({len(rows)} commands){R}")
        print_results(rows)
        return
 
    if args.query:
        query = " ".join(args.query)
        rows = search_all(query)
        print(f"\n  {CYN}{BLD}Search: \"{query}\"{R}  {GRY}({len(rows)} results){R}")
        print_results(rows, highlight=query)
 
 
if __name__ == "__main__":
    main()
