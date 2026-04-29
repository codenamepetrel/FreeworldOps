#!/bin/bash
##############################################
## Freeworld - Allergic to aluminum baby   ##
## OSCP Command DB - Installer             ##
##############################################
 
GREEN='\033[38;5;82m'
YELLOW='\033[38;5;220m'
CYAN='\033[38;5;51m'
RED='\033[38;5;196m'
RESET='\033[0m'
BOLD='\033[1m'
 
echo -e "${GREEN}${BOLD}"
echo "  ╔══════════════════════════════════════╗"
echo "  ║   OSCP Command DB - Installer       ║"
echo "  ║   Freeworld / 1337 Pete             ║"
echo "  ╚══════════════════════════════════════╝"
echo -e "${RESET}"
 
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="$HOME/.oscp"
BIN_PATH="/usr/local/bin/oscp"
 
# Create install dir
mkdir -p "$INSTALL_DIR"
 
# Copy scripts
cp "$SCRIPT_DIR/oscp_db_setup.py" "$INSTALL_DIR/"
cp "$SCRIPT_DIR/oscp.py" "$INSTALL_DIR/"
 
echo -e "${CYAN}[*] Building database...${RESET}"
python3 "$INSTALL_DIR/oscp_db_setup.py"
 
# Create the oscp command wrapper
cat > /tmp/oscp_wrapper << 'EOF'
#!/bin/bash
python3 "$HOME/.oscp/oscp.py" "$@"
EOF
 
sudo cp /tmp/oscp_wrapper "$BIN_PATH"
sudo chmod +x "$BIN_PATH"
 
echo -e "${GREEN}[+] Installed to ${BIN_PATH}${RESET}"
echo -e "${GREEN}[+] Database at ~/.oscp_commands.db${RESET}"
echo ""
echo -e "${YELLOW}${BOLD}Usage:${RESET}"
echo -e "  ${CYAN}oscp${RESET}                    # show all categories"
echo -e "  ${CYAN}oscp impacket${RESET}           # search impacket"
echo -e "  ${CYAN}oscp kerberos${RESET}           # search kerberos"
echo -e "  ${CYAN}oscp --cat privesc-linux${RESET} # linux privesc commands"
echo -e "  ${CYAN}oscp --cat ad${RESET}           # active directory commands"
echo -e "  ${CYAN}oscp --add${RESET}              # add your own command"
echo -e "  ${CYAN}oscp --list${RESET}             # list categories"
echo ""
echo -e "${GREEN}${BOLD}[+] All done! Type 'oscp' to get started.${RESET}"
 
