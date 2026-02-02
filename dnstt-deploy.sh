#!/bin/bash

# dnstt Server Setup Script
# Supports Fedora, Rocky, CentOS, Debian, Ubuntu

set -e

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo -e "\033[0;31m[ERROR]\033[0m This script must be run as root"
    exit 1
fi

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Global variables
DNSTT_BASE_URL="https://dnstt.network"
SCRIPT_URL="https://raw.githubusercontent.com/squirtea/dnstt-deploy/refs/heads/main/dnstt-deploy.sh"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/dnstt"
SYSTEMD_DIR="/etc/systemd/system"
DNSTT_PORT="5300"
DNSTT_USER="dnstt"
CONFIG_FILE="${CONFIG_DIR}/dnstt-server.conf"
SCRIPT_INSTALL_PATH="/usr/local/bin/dnstt-deploy"

# Global variable to track if update is available
UPDATE_AVAILABLE=false

# Function to install/update the script itself
install_script() {
    print_status "Installing/updating dnstt-deploy script..."

    # Download the latest version
    local temp_script="/tmp/dnstt-deploy-new.sh"
    curl -Ls "$SCRIPT_URL" -o "$temp_script"

    # Make it executable
    chmod +x "$temp_script"

    # Check if we're updating an existing installation
    if [ -f "$SCRIPT_INSTALL_PATH" ]; then
        # Compare checksums to see if update is needed
        local current_checksum
        local new_checksum
        current_checksum=$(sha256sum "$SCRIPT_INSTALL_PATH" | cut -d' ' -f1)
        new_checksum=$(sha256sum "$temp_script" | cut -d' ' -f1)

        if [ "$current_checksum" = "$new_checksum" ]; then
            print_status "Script is already up to date"
            rm "$temp_script"
            return 0
        else
            print_status "Updating existing script installation..."
        fi
    else
        print_status "Installing script for the first time..."
    fi

    # Copy to installation directory
    cp "$temp_script" "$SCRIPT_INSTALL_PATH"
    rm "$temp_script"

    print_status "Script installed to $SCRIPT_INSTALL_PATH"
    print_status "You can now run 'dnstt-deploy' from anywhere"
}

# Function to handle manual update
update_script() {
    print_status "Checking for script updates..."

    local temp_script="/tmp/dnstt-deploy-latest.sh"
    if ! curl -Ls "$SCRIPT_URL" -o "$temp_script"; then
        print_error "Failed to download latest version"
        return 1
    fi

    local current_checksum
    local latest_checksum
    current_checksum=$(sha256sum "$SCRIPT_INSTALL_PATH" | cut -d' ' -f1)
    latest_checksum=$(sha256sum "$temp_script" | cut -d' ' -f1)

    if [ "$current_checksum" = "$latest_checksum" ]; then
        print_status "You are already running the latest version"
        rm "$temp_script"
        return 0
    fi

    print_status "New version available! Updating..."
    chmod +x "$temp_script"
    cp "$temp_script" "$SCRIPT_INSTALL_PATH"
    rm "$temp_script"
    print_status "Script updated successfully!"
    print_status "Restarting with new version..."

    # Restart the script with the new version immediately
    exec "$SCRIPT_INSTALL_PATH"
}

# Function to show main menu
show_menu() {
    echo ""
    print_status "dnstt Server Management"
    print_status "======================="

    # Show update notification if available
    if [ "$UPDATE_AVAILABLE" = true ]; then
        echo -e "${YELLOW}[UPDATE AVAILABLE]${NC} A new version of this script is available!"
        echo -e "${YELLOW}                  ${NC} Use option 2 to update to the latest version."
        echo ""
    fi

    echo "1) Install/Reconfigure dnstt server"
    echo "2) Update dnstt-deploy script"
    echo "3) Check service status"
    echo "4) View service logs"
    echo "5) Show configuration info"
    echo "6) Uninstall dnstt"
    echo "0) Exit"
    echo ""
    print_question "Please select an option (0-6): "
}

# Function to handle menu selection
handle_menu() {
    while true; do
        show_menu
        read -r choice

        case $choice in
            1)
                print_status "Starting dnstt server installation/reconfiguration..."
                return 0  # Continue with main installation
                ;;
            2)
                update_script
                ;;
            3)
                if systemctl is-active --quiet dnstt-server; then
                    print_status "dnstt-server service is running"
                    systemctl status dnstt-server --no-pager -l
                else
                    print_warning "dnstt-server service is not running"
                    systemctl status dnstt-server --no-pager -l
                fi
                ;;
            4)
                print_status "Showing dnstt-server logs (Press Ctrl+C to exit)..."
                journalctl -u dnstt-server -f
                ;;
            5)
                show_configuration_info
                ;;
            6)
                if uninstall; then
                    exit 0
                fi
                ;;
            0)
                print_status "Goodbye!"
                exit 0
                ;;
            *)
                print_error "Invalid choice. Please enter 0-6."
                ;;
        esac

        if [ "$choice" != "4" ]; then
            echo ""
            print_question "Press Enter to continue..."
            read -r
        fi
    done
}

# Function to show configuration information
show_configuration_info() {
    print_status "Current Configuration Information"
    print_status "================================"

    # Check if configuration file exists
    if [ ! -f "$CONFIG_FILE" ]; then
        print_warning "No configuration found. Please install/configure dnstt server first."
        return 1
    fi

    # Load existing configuration
    if ! load_existing_config; then
        print_error "Failed to load configuration from $CONFIG_FILE"
        return 1
    fi

    # Check if service is running
    local service_status
    if systemctl is-active --quiet dnstt-server; then
        service_status="${GREEN}Running${NC}"
    else
        service_status="${RED}Stopped${NC}"
    fi

    echo ""
    echo -e "${BLUE}Configuration Details:${NC}"
    echo -e "  Nameserver subdomain: ${YELLOW}$DOMAIN${NC}"
    echo -e "  MTU: ${YELLOW}$MTU_VALUE${NC}"
    echo -e "  Tunnel mode: ${YELLOW}$TUNNEL_MODE${NC}"
    echo -e "  Service user: ${YELLOW}$DNSTT_USER${NC}"
    echo -e "  Listen port: ${YELLOW}$DNSTT_PORT${NC} (DNS traffic redirected from port 53)"
    echo -e "  Service status: $service_status"
    echo ""

    # Show public key if it exists
    if [ -f "$PUBLIC_KEY_FILE" ]; then
        echo -e "${BLUE}Public Key Content:${NC}"
        echo -e "${YELLOW}$(cat "$PUBLIC_KEY_FILE")${NC}"
        echo ""
    else
        print_warning "Public key file not found: $PUBLIC_KEY_FILE"
    fi

    echo -e "${BLUE}Management Commands:${NC}"
    echo -e "  Run menu:           ${YELLOW}dnstt-deploy${NC}"
    echo -e "  Start service:      ${YELLOW}systemctl start dnstt-server${NC}"
    echo -e "  Stop service:       ${YELLOW}systemctl stop dnstt-server${NC}"
    echo -e "  Service status:     ${YELLOW}systemctl status dnstt-server${NC}"
    echo -e "  View logs:          ${YELLOW}journalctl -u dnstt-server -f${NC}"

    # Show SOCKS info if applicable
    if [ "$TUNNEL_MODE" = "socks" ]; then
        echo ""
        echo -e "${BLUE}SOCKS Proxy Information:${NC}"
        echo -e "SOCKS proxy is running on ${YELLOW}127.0.0.1:1080${NC}"
        if [[ "${SOCKS_AUTH_ENABLED:-no}" == "yes" && -n "${SOCKS_USERNAME:-}" ]]; then
            echo -e "Authentication: ${GREEN}Enabled${NC} (username: ${YELLOW}$SOCKS_USERNAME${NC})"
        else
            echo -e "Authentication: ${YELLOW}Disabled${NC}"
        fi
        echo -e "${BLUE}Dante service commands:${NC}"
        echo -e "  Status:  ${YELLOW}systemctl status danted${NC}"
        echo -e "  Stop:    ${YELLOW}systemctl stop danted${NC}"
        echo -e "  Start:   ${YELLOW}systemctl start danted${NC}"
        echo -e "  Logs:    ${YELLOW}journalctl -u danted -f${NC}"
    fi

    # Show Shadowsocks info if applicable
    if [ "$TUNNEL_MODE" = "shadowsocks" ]; then
        echo ""
        echo -e "${BLUE}Shadowsocks Information:${NC}"
        echo -e "Shadowsocks server is running on ${YELLOW}127.0.0.1:${SHADOWSOCKS_PORT:-8388}${NC}"
        echo -e "Encryption method: ${YELLOW}${SHADOWSOCKS_METHOD:-aes-256-gcm}${NC}"
        echo -e "${BLUE}Shadowsocks service commands:${NC}"
        echo -e "  Status:  ${YELLOW}systemctl status shadowsocks-libev-server@config${NC}"
        echo -e "  Stop:    ${YELLOW}systemctl stop shadowsocks-libev-server@config${NC}"
        echo -e "  Start:   ${YELLOW}systemctl start shadowsocks-libev-server@config${NC}"
        echo -e "  Logs:    ${YELLOW}journalctl -u shadowsocks-libev-server@config -f${NC}"
    fi

    echo ""
}

check_for_updates() {
    # Only check for updates if we're running from the installed location
    if [ "$0" = "$SCRIPT_INSTALL_PATH" ]; then
        print_status "Checking for script updates..."

        local temp_script="/tmp/dnstt-deploy-latest.sh"
        if curl -Ls "$SCRIPT_URL" -o "$temp_script" 2>/dev/null; then
            local current_checksum
            local latest_checksum
            current_checksum=$(sha256sum "$SCRIPT_INSTALL_PATH" | cut -d' ' -f1)
            latest_checksum=$(sha256sum "$temp_script" | cut -d' ' -f1)

            if [ "$current_checksum" != "$latest_checksum" ]; then
                UPDATE_AVAILABLE=true
                print_warning "New version available! Use menu option 2 to update."
            else
                print_status "Script is up to date"
            fi
            rm "$temp_script"
        else
            print_warning "Could not check for updates (network issue)"
        fi
    fi
}

detect_active_mode() {
    if systemctl is-active --quiet shadowsocks-libev-server@config 2>/dev/null || \
       systemctl is-active --quiet shadowsocks-libev 2>/dev/null; then
        echo "shadowsocks"
        return 0
    fi

    if systemctl is-active --quiet danted 2>/dev/null; then
        echo "socks"
        return 0
    fi

    echo ""
    return 0
}

# Function to load existing configuration
load_existing_config() {
    if [ -f "$CONFIG_FILE" ]; then
        print_status "Loading existing configuration..."
        # Source the config file to load variables
        # shellcheck source=/dev/null
        . "$CONFIG_FILE"
        return 0
    fi
    return 1
}

# Function to save configuration
save_config() {
    print_status "Saving configuration..."

    cat > "$CONFIG_FILE" << EOF
# dnstt Server Configuration
# Generated on $(date)

DOMAIN="$DOMAIN"
MTU_VALUE="$MTU_VALUE"
TUNNEL_MODE="$TUNNEL_MODE"
PRIVATE_KEY_FILE="$PRIVATE_KEY_FILE"
PUBLIC_KEY_FILE="$PUBLIC_KEY_FILE"
EOF

    if [ "$TUNNEL_MODE" = "socks" ]; then
        cat >> "$CONFIG_FILE" << EOF
SOCKS_AUTH_ENABLED="${SOCKS_AUTH_ENABLED:-no}"
SOCKS_USERNAME="${SOCKS_USERNAME:-}"
SOCKS_PASSWORD="${SOCKS_PASSWORD:-}"
EOF
    fi

    if [ "$TUNNEL_MODE" = "shadowsocks" ]; then
        cat >> "$CONFIG_FILE" << EOF
SHADOWSOCKS_PORT="${SHADOWSOCKS_PORT:-8388}"
SHADOWSOCKS_PASSWORD="${SHADOWSOCKS_PASSWORD:-}"
SHADOWSOCKS_METHOD="${SHADOWSOCKS_METHOD:-aes-256-gcm}"
EOF
    fi

    chmod 640 "$CONFIG_FILE"
    chown root:"$DNSTT_USER" "$CONFIG_FILE"
    print_status "Configuration saved to $CONFIG_FILE"
}

print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_question() {
    echo -ne "${BLUE}[QUESTION]${NC} $1"
}

# Function to print success box without [INFO] prefix
print_success_box() {
    local border_color='\033[1;32m'  # Bright green
    local text_color='\033[1;37m'    # Bright white text
    local key_color='\033[1;33m'     # Yellow for key
    local header_color='\033[1;36m'  # Cyan for headers
    local reset='\033[0m'

    echo ""
    # Top border
    echo -e "${border_color}+================================================================================${reset}"
    echo -e "${border_color}|                          SETUP COMPLETED SUCCESSFULLY!                       |${reset}"
    echo -e "${border_color}+================================================================================${reset}"
    echo ""

    # Configuration Details
    echo -e "${header_color}Configuration Details:${reset}"
    echo -e "  ${text_color}Nameserver subdomain: $DOMAIN${reset}"
    echo -e "  ${text_color}MTU: $MTU_VALUE${reset}"
    echo -e "  ${text_color}Tunnel mode: $TUNNEL_MODE${reset}"
    echo -e "  ${text_color}Service user: $DNSTT_USER${reset}"
    echo -e "  ${text_color}Listen port: $DNSTT_PORT (DNS traffic redirected from port 53)${reset}"
    echo ""

    # Public Key
    echo -e "${header_color}Public Key Content:${reset}"
    local pub_key_content
    pub_key_content=$(cat "$PUBLIC_KEY_FILE")
    echo -e "${key_color}$pub_key_content${reset}"
    echo ""

    # Script Location
    echo -e "${text_color}Script installed at: $SCRIPT_INSTALL_PATH${reset}"
    echo ""

    # Management Commands
    echo -e "${header_color}Management Commands:${reset}"
    echo -e "  ${text_color}Run menu:           dnstt-deploy${reset}"
    echo -e "  ${text_color}Start service:      systemctl start dnstt-server${reset}"
    echo -e "  ${text_color}Stop service:       systemctl stop dnstt-server${reset}"
    echo -e "  ${text_color}Service status:     systemctl status dnstt-server${reset}"
    echo -e "  ${text_color}View logs:          journalctl -u dnstt-server -f${reset}"

    # SOCKS info if applicable
    if [ "$TUNNEL_MODE" = "socks" ]; then
        echo ""
        echo -e "${header_color}SOCKS Proxy Information:${reset}"
        echo -e "${text_color}SOCKS proxy is running on 127.0.0.1:1080${reset}"
        if [[ "${SOCKS_AUTH_ENABLED:-no}" == "yes" && -n "${SOCKS_USERNAME:-}" ]]; then
            echo -e "${text_color}Authentication: ${key_color}Enabled${reset} (username: ${key_color}$SOCKS_USERNAME${reset})"
        else
            echo -e "${text_color}Authentication: ${key_color}Disabled${reset}"
        fi
        echo -e "${text_color}Dante service commands:${reset}"
        echo -e "  ${text_color}Status:  systemctl status danted${reset}"
        echo -e "  ${text_color}Stop:    systemctl stop danted${reset}"
        echo -e "  ${text_color}Start:   systemctl start danted${reset}"
        echo -e "  ${text_color}Logs:    journalctl -u danted -f${reset}"
    fi

    # Shadowsocks info if applicable
    if [ "$TUNNEL_MODE" = "shadowsocks" ]; then
        echo ""
        echo -e "${header_color}Shadowsocks Information:${reset}"
        echo -e "${text_color}Shadowsocks server is running on 127.0.0.1:${SHADOWSOCKS_PORT:-8388}${reset}"
        echo -e "${text_color}Encryption method: ${key_color}${SHADOWSOCKS_METHOD:-aes-256-gcm}${reset}"
        echo -e "${text_color}Shadowsocks service commands:${reset}"
        echo -e "  ${text_color}Status:  systemctl status shadowsocks-libev-server@config${reset}"
        echo -e "  ${text_color}Stop:    systemctl stop shadowsocks-libev-server@config${reset}"
        echo -e "  ${text_color}Start:   systemctl start shadowsocks-libev-server@config${reset}"
        echo -e "  ${text_color}Logs:    journalctl -u shadowsocks-libev-server@config -f${reset}"
    fi

    # Bottom border
    echo ""
    echo -e "${border_color}+================================================================================${reset}"
    echo ""
}

# Function to print info lines without [INFO] prefix for final display
print_info_line() {
    local text_color='\033[1;37m'    # Bright white
    local reset='\033[0m'
    echo -e "${text_color}$1${reset}"
}

# Function to print section headers in final display
print_section_header() {
    local header_color='\033[1;36m'  # Bright cyan
    local reset='\033[0m'
    echo -e "${header_color}$1${reset}"
}

# Function to detect OS and package manager
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$NAME
    else
        print_error "Cannot detect OS"
        exit 1
    fi

    # Determine package manager
    if command -v dnf &> /dev/null; then
        PKG_MANAGER="dnf"
    elif command -v yum &> /dev/null; then
        PKG_MANAGER="yum"
    elif command -v apt &> /dev/null; then
        PKG_MANAGER="apt"
    else
        print_error "Unsupported package manager"
        exit 1
    fi

    print_status "Detected OS: $OS"
    print_status "Package manager: $PKG_MANAGER"
}

# Function to detect architecture
detect_arch() {
    local arch
    arch=$(uname -m)
    case $arch in
        x86_64)
            ARCH="amd64"
            ;;
        aarch64|arm64)
            ARCH="arm64"
            ;;
        armv7l|armv6l)
            ARCH="arm"
            ;;
        i386|i686)
            ARCH="386"
            ;;
        *)
            print_error "Unsupported architecture: $arch"
            exit 1
            ;;
    esac
    print_status "Detected architecture: $ARCH"
}

# Function to check and install required tools
check_required_tools() {
    print_status "Checking required tools..."

    local required_tools=("curl")
    local missing_tools=()

    # Check which tools are missing
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
        fi
    done

    # Check for iptables separately since it might need special handling
    if ! command -v "iptables" &> /dev/null; then
        missing_tools+=("iptables")
    fi

    if [ ${#missing_tools[@]} -gt 0 ]; then
        print_status "Installing missing tools: ${missing_tools[*]}"
        install_dependencies "${missing_tools[@]}"
    else
        print_status "All required tools are available"
    fi

    # Verify iptables installation after potential installation
    verify_iptables_installation
}

# Function to verify iptables installation and capabilities
verify_iptables_installation() {
    print_status "Verifying iptables installation..."

    if ! command -v iptables &> /dev/null; then
        print_error "iptables is not available after installation attempt"
        exit 1
    fi

    # Check if ip6tables is available (should be part of iptables package)
    if command -v ip6tables &> /dev/null; then
        print_status "Both iptables and ip6tables are available"
    else
        print_warning "ip6tables not found, IPv6 rules will be skipped"
    fi

    # Check if IPv6 is supported on the system
    if [ -f /proc/net/if_inet6 ]; then
        print_status "IPv6 support detected"
    else
        print_warning "IPv6 not supported on this system"
    fi
}

# Function to install dependencies
install_dependencies() {
    local tools=("$@")
    print_status "Installing dependencies: ${tools[*]}"

    # Safety check for PKG_MANAGER
    if [[ -z "$PKG_MANAGER" ]]; then
        print_error "Package manager not detected. Make sure detect_os() is called first."
        exit 1
    fi

    case $PKG_MANAGER in
        dnf|yum)
            # For RHEL-based systems
            local packages_to_install=()

            for tool in "${tools[@]}"; do
                case $tool in
                    "iptables")
                        packages_to_install+=("iptables" "iptables-services")
                        ;;
                    *)
                        packages_to_install+=("$tool")
                        ;;
                esac
            done

            if ! $PKG_MANAGER install -y "${packages_to_install[@]}"; then
                print_error "Failed to install packages: ${packages_to_install[*]}"
                exit 1
            fi
            ;;
        apt)
            # For Debian-based systems
            if ! apt update; then
                print_error "Failed to update package lists"
                exit 1
            fi

            local packages_to_install=()

            for tool in "${tools[@]}"; do
                case $tool in
                    "iptables")
                        # iptables package includes both iptables and ip6tables
                        packages_to_install+=("iptables" "iptables-persistent")
                        ;;
                    *)
                        packages_to_install+=("$tool")
                        ;;
                esac
            done

            if ! apt install -y "${packages_to_install[@]}"; then
                print_error "Failed to install packages: ${packages_to_install[*]}"
                exit 1
            fi
            ;;
        *)
            print_error "Unsupported package manager: $PKG_MANAGER"
            exit 1
            ;;
    esac

    print_status "Dependencies installed successfully"
}

# Function to get user input
get_user_input() {
    local existing_domain=""
    local existing_mtu=""
    local existing_mode=""
    local existing_ss_port=""
    local existing_ss_method=""
    local existing_ss_password=""
    local existing_auth=""
    local existing_username=""

    if load_existing_config; then
        existing_domain="$DOMAIN"
        existing_mtu="$MTU_VALUE"
        existing_mode="$TUNNEL_MODE"
        # Save Shadowsocks config if it exists
        existing_ss_port="${SHADOWSOCKS_PORT:-}"
        existing_ss_method="${SHADOWSOCKS_METHOD:-}"
        existing_ss_password="${SHADOWSOCKS_PASSWORD:-}"
        # Save SOCKS config if it exists
        existing_auth="${SOCKS_AUTH_ENABLED:-}"
        existing_username="${SOCKS_USERNAME:-}"
        print_status "Found existing configuration for domain: $existing_domain"
        # Clear TUNNEL_MODE so user's selection isn't overwritten
        unset TUNNEL_MODE
    fi

    local active_mode
    active_mode=$(detect_active_mode)
    if [[ -n "$active_mode" ]]; then
        existing_mode="$active_mode"
        print_status "Detected active tunnel mode: $active_mode"
    fi

    # Get domain
    while true; do
        if [[ -n "$existing_domain" ]]; then
            print_question "Enter the domain (current: $existing_domain): "
        else
            print_question "Enter the domain (e.g., s.example.com): "
        fi
        read -r DOMAIN

        # Use existing domain if user just presses enter
        if [[ -z "$DOMAIN" && -n "$existing_domain" ]]; then
            DOMAIN="$existing_domain"
        fi

        if [[ -n "$DOMAIN" ]]; then
            break
        else
            print_error "Please enter a valid domain"
        fi
    done

    # Get MTU value
    if [[ -n "$existing_mtu" ]]; then
        print_question "Enter MTU value (current: $existing_mtu): "
    else
        print_question "Enter MTU value (default: 1232): "
    fi
    read -r MTU_VALUE

    # Use existing MTU if user just presses enter, otherwise use default
    if [[ -z "$MTU_VALUE" ]]; then
        if [[ -n "$existing_mtu" ]]; then
            MTU_VALUE="$existing_mtu"
        else
            MTU_VALUE="1232"
        fi
    fi

    # Get tunnel mode
    while true; do
        echo "Select tunnel mode:"
        echo "1) SOCKS proxy (Dante)"
        echo "2) SSH mode"
        echo "3) Shadowsocks"
        if [[ -n "$existing_mode" ]]; then
            local mode_number
            case "$existing_mode" in
                socks) mode_number="1" ;;
                ssh) mode_number="2" ;;
                shadowsocks) mode_number="3" ;;
                *) mode_number="?" ;;
            esac
            print_question "Enter choice (current: $mode_number - $existing_mode): "
        else
            print_question "Enter choice (1, 2, or 3): "
        fi
        read -r TUNNEL_MODE

        # Use existing mode if user just presses enter
        if [[ -z "$TUNNEL_MODE" && -n "$existing_mode" ]]; then
            TUNNEL_MODE="$existing_mode"
            break
        fi

        case $TUNNEL_MODE in
            1)
                TUNNEL_MODE="socks"
                break
                ;;
            2)
                TUNNEL_MODE="ssh"
                break
                ;;
            3)
                TUNNEL_MODE="shadowsocks"
                break
                ;;
            *)
                print_error "Invalid choice. Please enter 1, 2, or 3"
                ;;
        esac
    done

    # Capture selected mode so it is not overwritten by any config reload; use this for all mode-specific prompts
    local selected_tunnel_mode="$TUNNEL_MODE"

    SOCKS_AUTH_ENABLED="no"
    SOCKS_USERNAME=""
    SOCKS_PASSWORD=""

    if [ "$selected_tunnel_mode" = "socks" ]; then
        # Use saved SOCKS config from initial load (no need to reload)

        while true; do
            if [[ -n "${existing_auth:-}" ]]; then
                local auth_status="disabled"
                if [[ "$existing_auth" == "yes" ]]; then
                    auth_status="enabled"
                fi
                print_question "Enable username/password authentication for SOCKS proxy? (current: $auth_status) [y/N]: "
            else
                print_question "Enable username/password authentication for SOCKS proxy? [y/N]: "
            fi
            read -r enable_auth

            if [[ -z "$enable_auth" && -n "${existing_auth:-}" ]]; then
                SOCKS_AUTH_ENABLED="$existing_auth"
                if [[ "$existing_auth" == "yes" ]]; then
                    SOCKS_USERNAME="$existing_username"
                fi
                break
            fi

            case $enable_auth in
                [Yy]|[Yy][Ee][Ss])
                    SOCKS_AUTH_ENABLED="yes"

                    while true; do
                        if [[ -n "${existing_username:-}" && "$SOCKS_AUTH_ENABLED" == "yes" ]]; then
                            print_question "Enter SOCKS username (current: $existing_username): "
                        else
                            print_question "Enter SOCKS username: "
                        fi
                        read -r SOCKS_USERNAME

                        if [[ -z "$SOCKS_USERNAME" && -n "${existing_username:-}" ]]; then
                            SOCKS_USERNAME="$existing_username"
                        fi

                        if [[ -n "$SOCKS_USERNAME" ]]; then
                            break
                        else
                            print_error "Please enter a valid username"
                        fi
                    done

                    while true; do
                        print_question "Enter SOCKS password: "
                        read -rs SOCKS_PASSWORD
                        echo ""  # New line after hidden password input

                        if [[ -z "$SOCKS_PASSWORD" ]]; then
                            print_error "Please enter a valid password"
                        else
                            print_question "Confirm SOCKS password: "
                            read -rs SOCKS_PASSWORD_CONFIRM
                            echo ""  # New line after hidden password input

                            if [[ "$SOCKS_PASSWORD" != "$SOCKS_PASSWORD_CONFIRM" ]]; then
                                print_error "Passwords do not match. Please try again."
                                SOCKS_PASSWORD=""
                            else
                                break
                            fi
                        fi
                    done
                    break
                    ;;
                [Nn]|[Nn][Oo]|"")
                    SOCKS_AUTH_ENABLED="no"
                    break
                    ;;
                *)
                    print_error "Invalid choice. Please enter y or n"
                    ;;
            esac
        done
    fi

    # Shadowsocks configuration
    SHADOWSOCKS_PORT="8388"
    SHADOWSOCKS_PASSWORD=""
    SHADOWSOCKS_METHOD="aes-256-gcm"

    if [ "$selected_tunnel_mode" = "shadowsocks" ]; then
        # Use saved Shadowsocks config from initial load (no need to reload)
        # Variables are already saved as existing_ss_port, existing_ss_method, existing_ss_password

        # Get Shadowsocks port
        while true; do
            if [[ -n "${existing_ss_port:-}" ]]; then
                print_question "Enter Shadowsocks local port (current: $existing_ss_port): "
            else
                print_question "Enter Shadowsocks local port (default: 8388): "
            fi
            read -r input_port

            if [[ -z "$input_port" ]]; then
                if [[ -n "${existing_ss_port:-}" ]]; then
                    SHADOWSOCKS_PORT="$existing_ss_port"
                else
                    SHADOWSOCKS_PORT="8388"
                fi
                break
            elif [[ "$input_port" =~ ^[0-9]+$ ]] && [ "$input_port" -ge 1 ] && [ "$input_port" -le 65535 ]; then
                SHADOWSOCKS_PORT="$input_port"
                break
            else
                print_error "Please enter a valid port number (1-65535)"
            fi
        done

        # Get Shadowsocks password
        while true; do
            print_question "Enter Shadowsocks password: "
            read -rs SHADOWSOCKS_PASSWORD
            echo ""

            if [[ -z "$SHADOWSOCKS_PASSWORD" ]]; then
                print_error "Please enter a valid password"
            else
                print_question "Confirm Shadowsocks password: "
                read -rs SHADOWSOCKS_PASSWORD_CONFIRM
                echo ""

                if [[ "$SHADOWSOCKS_PASSWORD" != "$SHADOWSOCKS_PASSWORD_CONFIRM" ]]; then
                    print_error "Passwords do not match. Please try again."
                    SHADOWSOCKS_PASSWORD=""
                else
                    break
                fi
            fi
        done

        # Get encryption method
        echo "Select encryption method:"
        echo "1) aes-256-gcm (recommended)"
        echo "2) aes-128-gcm"
        echo "3) chacha20-ietf-poly1305"
        echo "4) aes-256-cfb"
        echo "5) aes-128-cfb"
        while true; do
            if [[ -n "${existing_ss_method:-}" ]]; then
                print_question "Enter choice (current: $existing_ss_method): "
            else
                print_question "Enter choice (default: 1): "
            fi
            read -r method_choice

            if [[ -z "$method_choice" ]]; then
                if [[ -n "${existing_ss_method:-}" ]]; then
                    SHADOWSOCKS_METHOD="$existing_ss_method"
                else
                    SHADOWSOCKS_METHOD="aes-256-gcm"
                fi
                break
            fi

            case $method_choice in
                1) SHADOWSOCKS_METHOD="aes-256-gcm"; break ;;
                2) SHADOWSOCKS_METHOD="aes-128-gcm"; break ;;
                3) SHADOWSOCKS_METHOD="chacha20-ietf-poly1305"; break ;;
                4) SHADOWSOCKS_METHOD="aes-256-cfb"; break ;;
                5) SHADOWSOCKS_METHOD="aes-128-cfb"; break ;;
                *) print_error "Invalid choice. Please enter 1-5" ;;
            esac
        done
    fi

    # Ensure TUNNEL_MODE is set from user's selection for save_config and rest of script
    TUNNEL_MODE="$selected_tunnel_mode"

    print_status "Configuration:"
    print_status "  Domain: $DOMAIN"
    print_status "  MTU: $MTU_VALUE"
    print_status "  Tunnel mode: $TUNNEL_MODE"
    if [ "$TUNNEL_MODE" = "socks" ]; then
        if [ "$SOCKS_AUTH_ENABLED" = "yes" ]; then
            print_status "  SOCKS authentication: enabled (username: $SOCKS_USERNAME)"
        else
            print_status "  SOCKS authentication: disabled"
        fi
    fi
    if [ "$TUNNEL_MODE" = "shadowsocks" ]; then
        print_status "  Shadowsocks port: $SHADOWSOCKS_PORT"
        print_status "  Shadowsocks method: $SHADOWSOCKS_METHOD"
    fi
}

# Function to download and verify dnstt-server
download_dnstt_server() {
    local filename="dnstt-server-linux-${ARCH}"
    local filepath="${INSTALL_DIR}/dnstt-server"

    # Check if file already exists
    if [ -f "$filepath" ]; then
        print_status "dnstt-server already exists at $filepath"
        return 0
    fi

    print_status "Downloading dnstt-server..."

    # Download the binary
    curl -L -o "/tmp/$filename" "${DNSTT_BASE_URL}/$filename"

    # Download checksums
    curl -L -o "/tmp/MD5SUMS" "${DNSTT_BASE_URL}/MD5SUMS"
    curl -L -o "/tmp/SHA1SUMS" "${DNSTT_BASE_URL}/SHA1SUMS"
    curl -L -o "/tmp/SHA256SUMS" "${DNSTT_BASE_URL}/SHA256SUMS"

    # Verify checksums
    print_status "Verifying file integrity..."

    cd /tmp

    # Verify MD5
    if md5sum -c <(grep "$filename" MD5SUMS) 2>/dev/null; then
        print_status "MD5 checksum verified"
    else
        print_error "MD5 checksum verification failed"
        exit 1
    fi

    # Verify SHA1
    if sha1sum -c <(grep "$filename" SHA1SUMS) 2>/dev/null; then
        print_status "SHA1 checksum verified"
    else
        print_error "SHA1 checksum verification failed"
        exit 1
    fi

    # Verify SHA256
    if sha256sum -c <(grep "$filename" SHA256SUMS) 2>/dev/null; then
        print_status "SHA256 checksum verified"
    else
        print_error "SHA256 checksum verification failed"
        exit 1
    fi

    # Move to install directory and make executable
    chmod +x "/tmp/$filename"
    mv "/tmp/$filename" "$filepath"

    print_status "dnstt-server installed successfully"
}

# Function to create dnstt user
create_dnstt_user() {
    print_status "Creating dnstt user..."

    if ! id "$DNSTT_USER" &>/dev/null; then
        useradd -r -s /bin/false -d /nonexistent -c "dnstt service user" "$DNSTT_USER"
        print_status "Created user: $DNSTT_USER"
    else
        print_status "User $DNSTT_USER already exists"
    fi

    # Create config directory first
    mkdir -p "$CONFIG_DIR"

    # Set ownership of config directory
    chown -R "$DNSTT_USER":"$DNSTT_USER" "$CONFIG_DIR"
    chmod 750 "$CONFIG_DIR"
}

# Function to generate keys
generate_keys() {
    # Generate key file names based on subdomain
    local key_prefix
    # shellcheck disable=SC2001
    key_prefix=$(echo "$DOMAIN" | sed 's/\./_/g')
    PRIVATE_KEY_FILE="${CONFIG_DIR}/${key_prefix}_server.key"
    PUBLIC_KEY_FILE="${CONFIG_DIR}/${key_prefix}_server.pub"

    # Check if keys already exist for this domain
    if [[ -f "$PRIVATE_KEY_FILE" && -f "$PUBLIC_KEY_FILE" ]]; then
        print_status "Found existing keys for domain: $DOMAIN"
        print_status "  Private key: $PRIVATE_KEY_FILE"
        print_status "  Public key: $PUBLIC_KEY_FILE"

        # Verify key ownership and permissions
        chown "$DNSTT_USER":"$DNSTT_USER" "$PRIVATE_KEY_FILE" "$PUBLIC_KEY_FILE"
        chmod 600 "$PRIVATE_KEY_FILE"
        chmod 644 "$PUBLIC_KEY_FILE"

        print_status "Using existing keys (verified ownership and permissions)"
    else
        print_status "Generating new keys for domain: $DOMAIN"

        # Generate keys (run as root, then change ownership)
        dnstt-server -gen-key -privkey-file "$PRIVATE_KEY_FILE" -pubkey-file "$PUBLIC_KEY_FILE"

        # Set proper ownership and permissions
        chown "$DNSTT_USER":"$DNSTT_USER" "$PRIVATE_KEY_FILE" "$PUBLIC_KEY_FILE"
        chmod 600 "$PRIVATE_KEY_FILE"
        chmod 644 "$PUBLIC_KEY_FILE"

        print_status "New keys generated:"
        print_status "  Private key: $PRIVATE_KEY_FILE"
        print_status "  Public key: $PUBLIC_KEY_FILE"
    fi

    # Always display public key content
    print_status "Public key content:"
    cat "$PUBLIC_KEY_FILE"
}

# Function to configure iptables rules
configure_iptables() {
    print_status "Configuring iptables rules for DNS redirection..."

    # Verify iptables is available
    if ! command -v iptables &> /dev/null; then
        print_error "iptables command not found. Cannot configure firewall rules."
        exit 1
    fi

    # Get the primary network interface
    local interface
    interface=$(ip route | grep default | awk '{print $5}' | head -1)
    if [[ -z "$interface" ]]; then
        # Try alternative method to get interface
        interface=$(ip link show | grep -E "^[0-9]+: (eth|ens|enp)" | head -1 | cut -d':' -f2 | awk '{print $1}')
        if [[ -z "$interface" ]]; then
            interface="eth0"  # fallback
            print_warning "Could not detect network interface, using eth0 as fallback"
        else
            print_status "Detected network interface: $interface"
        fi
    else
        print_status "Using network interface: $interface"
    fi

    # IPv4 rules
    print_status "Setting up IPv4 iptables rules..."

    if ! iptables -I INPUT -p udp --dport "$DNSTT_PORT" -j ACCEPT; then
        print_error "Failed to add IPv4 INPUT rule"
        exit 1
    fi

    if ! iptables -t nat -I PREROUTING -i "$interface" -p udp --dport 53 -j REDIRECT --to-ports "$DNSTT_PORT"; then
        print_error "Failed to add IPv4 NAT rule"
        exit 1
    fi

    print_status "IPv4 iptables rules configured successfully"

    # IPv6 rules (if IPv6 and ip6tables are available)
    if command -v ip6tables &> /dev/null && [ -f /proc/net/if_inet6 ]; then
        print_status "Setting up IPv6 iptables rules..."

        if ip6tables -I INPUT -p udp --dport "$DNSTT_PORT" -j ACCEPT 2>/dev/null; then
            print_status "IPv6 INPUT rule added successfully"
        else
            print_warning "Failed to add IPv6 INPUT rule (IPv6 might not be fully configured)"
        fi

        if ip6tables -t nat -I PREROUTING -i "$interface" -p udp --dport 53 -j REDIRECT --to-ports "$DNSTT_PORT" 2>/dev/null; then
            print_status "IPv6 NAT rule added successfully"
        else
            print_warning "Failed to add IPv6 NAT rule (IPv6 NAT might not be supported)"
        fi
    else
        if ! command -v ip6tables &> /dev/null; then
            print_warning "ip6tables not available, skipping IPv6 rules"
        elif [ ! -f /proc/net/if_inet6 ]; then
            print_warning "IPv6 not enabled on system, skipping IPv6 rules"
        fi
    fi

    # Save iptables rules based on distribution
    save_iptables_rules
}

# Function to save iptables rules with better error handling
save_iptables_rules() {
    print_status "Saving iptables rules..."

    case $PKG_MANAGER in
        dnf|yum)
            # For RHEL-based systems
            if command -v iptables-save &> /dev/null; then
                # Create directory if it doesn't exist
                mkdir -p /etc/sysconfig

                if iptables-save > /etc/sysconfig/iptables; then
                    print_status "IPv4 iptables rules saved to /etc/sysconfig/iptables"
                else
                    print_warning "Failed to save IPv4 iptables rules"
                fi

                if command -v ip6tables-save &> /dev/null && [ -f /proc/net/if_inet6 ]; then
                    if ip6tables-save > /etc/sysconfig/ip6tables; then
                        print_status "IPv6 iptables rules saved to /etc/sysconfig/ip6tables"
                    else
                        print_warning "Failed to save IPv6 iptables rules"
                    fi
                fi

                # Enable and start iptables service if available
                if systemctl list-unit-files | grep -q iptables.service; then
                    systemctl enable iptables 2>/dev/null || print_warning "Could not enable iptables service"
                    if command -v ip6tables &> /dev/null && [ -f /proc/net/if_inet6 ]; then
                        systemctl enable ip6tables 2>/dev/null || print_warning "Could not enable ip6tables service"
                    fi
                fi
            else
                print_warning "iptables-save not available, rules will not persist after reboot"
            fi
            ;;
        apt)
            # For Debian-based systems
            if command -v iptables-save &> /dev/null; then
                # Create directory if it doesn't exist
                mkdir -p /etc/iptables

                if iptables-save > /etc/iptables/rules.v4; then
                    print_status "IPv4 iptables rules saved to /etc/iptables/rules.v4"
                else
                    print_warning "Failed to save IPv4 iptables rules"
                fi

                if command -v ip6tables-save &> /dev/null && [ -f /proc/net/if_inet6 ]; then
                    if ip6tables-save > /etc/iptables/rules.v6; then
                        print_status "IPv6 iptables rules saved to /etc/iptables/rules.v6"
                    else
                        print_warning "Failed to save IPv6 iptables rules"
                    fi
                fi

                # Try to enable netfilter-persistent if available
                if systemctl list-unit-files | grep -q netfilter-persistent.service; then
                    systemctl enable netfilter-persistent 2>/dev/null || print_warning "Could not enable netfilter-persistent service"
                fi
            else
                print_warning "iptables-save not available, rules will not persist after reboot"
            fi
            ;;
    esac
}

# Function to configure firewall
configure_firewall() {
    print_status "Configuring firewall..."

    # Check if firewalld is available and active
    if command -v firewall-cmd &> /dev/null && systemctl is-active --quiet firewalld; then
        print_status "Configuring active firewalld..."
        firewall-cmd --permanent --add-port="$DNSTT_PORT"/udp
        firewall-cmd --permanent --add-port=53/udp
        firewall-cmd --reload
        print_status "Firewalld configured successfully"

    # Check if ufw is available and active
    elif command -v ufw &> /dev/null && ufw status | grep -q "Status: active"; then
        print_status "Configuring active ufw..."
        ufw allow "$DNSTT_PORT"/udp
        ufw allow 53/udp
        print_status "UFW configured successfully"

    else
        print_status "No active firewall service detected"
        print_status "Available firewall tools:"

        # List available but inactive firewall tools
        if command -v firewall-cmd &> /dev/null; then
            print_status "  - firewalld (inactive)"
        fi
        if command -v ufw &> /dev/null; then
            print_status "  - ufw (inactive)"
        fi

        print_status "Relying on iptables rules only"
        print_status "If you have a firewall active, manually allow ports $DNSTT_PORT/udp and 53/udp"
    fi

    # Configure iptables rules regardless of firewall service
    configure_iptables
}

# Function to detect SSH port
detect_ssh_port() {
    local ssh_port
    ssh_port=$(ss -tlnp | grep sshd | awk '{print $4}' | cut -d':' -f2 | head -1)
    if [[ -z "$ssh_port" ]]; then
        # Fallback to default SSH port
        ssh_port="22"
    fi
    echo "$ssh_port"
}

# Function to install and configure Dante SOCKS proxy
setup_dante() {
    print_status "Setting up Dante SOCKS proxy..."

    # Install Dante
    case $PKG_MANAGER in
        dnf|yum)
            $PKG_MANAGER install -y dante-server
            ;;
        apt)
            apt install -y dante-server
            ;;
    esac

    # Get the primary network interface for external interface
    local external_interface
    external_interface=$(ip route | grep default | awk '{print $5}' | head -1)
    if [[ -z "$external_interface" ]]; then
        external_interface="eth0"  # fallback
    fi

    local socks_method="none"

    if [[ "${SOCKS_AUTH_ENABLED:-no}" == "yes" && -n "${SOCKS_USERNAME:-}" && -n "${SOCKS_PASSWORD:-}" ]]; then
        socks_method="username"

        if ! id "$SOCKS_USERNAME" &>/dev/null; then
            print_status "Creating system user for SOCKS authentication: $SOCKS_USERNAME"
            useradd -r -s /bin/false -M "$SOCKS_USERNAME" 2>/dev/null || {
                print_error "Failed to create system user: $SOCKS_USERNAME"
                return 1
            }
            print_status "System user created: $SOCKS_USERNAME"
        else
            print_status "System user already exists: $SOCKS_USERNAME"
        fi

        print_status "Setting password for SOCKS user: $SOCKS_USERNAME"
        echo "$SOCKS_USERNAME:$SOCKS_PASSWORD" | chpasswd 2>/dev/null || {
            print_error "Failed to set password for user: $SOCKS_USERNAME"
            return 1
        }
        print_status "Password set successfully for SOCKS user"
    fi

    # Configure Dante
    cat > /etc/danted.conf << EOF
# Dante SOCKS server configuration
logoutput: syslog
user.privileged: root
user.unprivileged: nobody

# Internal interface (where clients connect)
internal: 127.0.0.1 port = 1080

# External interface (where connections go out)
external: $external_interface

# Authentication method
socksmethod: $socks_method
EOF

    cat >> /etc/danted.conf << EOF

# Compatibility settings
compatibility: sameport
extension: bind

# Client rules - allow connections from localhost
client pass {
    from: 127.0.0.0/8 to: 0.0.0.0/0
    log: error
}

# SOCKS rules - allow SOCKS requests to anywhere
socks pass {
    from: 127.0.0.0/8 to: 0.0.0.0/0
    command: bind connect udpassociate
EOF

    if [[ -n "$passwd_file" ]]; then
        cat >> /etc/danted.conf << EOF
    method: username
EOF
    fi

    cat >> /etc/danted.conf << EOF
    log: error
}

# Block IPv6 if not properly configured
socks block {
    from: 0.0.0.0/0 to: ::/0
    log: error
}

client block {
    from: 0.0.0.0/0 to: ::/0
    log: error
}
EOF

    # Enable and start Dante service
    systemctl enable danted
    systemctl restart danted

    print_status "Dante SOCKS proxy configured and started on port 1080"
    print_status "External interface: $external_interface"
    if [[ "$socks_method" == "username" ]]; then
        print_status "SOCKS authentication: enabled (username: $SOCKS_USERNAME)"
    else
        print_status "SOCKS authentication: disabled"
    fi
}

# Function to install and configure Shadowsocks
setup_shadowsocks() {
    print_status "Setting up Shadowsocks..."

    local shadowsocks_installed=false

    # First, try snap (recommended method)
    if command -v snap &> /dev/null; then
        print_status "Attempting to install shadowsocks-libev via snap..."
        if snap install shadowsocks-libev 2>/dev/null; then
            shadowsocks_installed=true
            print_status "Successfully installed shadowsocks-libev via snap"
        else
            print_warning "Failed to install shadowsocks-libev via snap, trying package manager..."
        fi
    else
        print_status "snap not available, trying package manager..."
    fi

    # If snap failed or not available, try package manager
    if [ "$shadowsocks_installed" = false ]; then
        case $PKG_MANAGER in
            dnf|yum)
                print_status "Attempting to install shadowsocks-libev via $PKG_MANAGER..."
                # Enable EPEL repository for shadowsocks-libev
                $PKG_MANAGER install -y epel-release 2>/dev/null || true
                if $PKG_MANAGER install -y shadowsocks-libev; then
                    shadowsocks_installed=true
                    print_status "Successfully installed shadowsocks-libev via $PKG_MANAGER"
                else
                    print_error "Failed to install shadowsocks-libev via $PKG_MANAGER"
                fi
                ;;
            apt)
                print_status "Attempting to install shadowsocks-libev via apt..."
                if apt update && apt install -y shadowsocks-libev; then
                    shadowsocks_installed=true
                    print_status "Successfully installed shadowsocks-libev via apt"
                else
                    print_error "Failed to install shadowsocks-libev via apt"
                fi
                ;;
            *)
                print_error "Unsupported package manager: $PKG_MANAGER"
                ;;
        esac
    fi

    # If installation failed, exit with error
    if [ "$shadowsocks_installed" = false ]; then
        print_error "Failed to install shadowsocks-libev via snap or package manager"
        print_error "Please install shadowsocks-libev manually and try again"
        exit 1
    fi

    # Determine config path: snap is confined and can only read from its common directory
    local shadowsocks_config_dir
    local shadowsocks_config_file
    if command -v snap &> /dev/null && snap list shadowsocks-libev &>/dev/null; then
        shadowsocks_config_dir="/var/snap/shadowsocks-libev/common/etc/shadowsocks-libev"
    else
        shadowsocks_config_dir="/etc/shadowsocks-libev"
    fi
    shadowsocks_config_file="${shadowsocks_config_dir}/config.json"

    # Create Shadowsocks configuration directory
    mkdir -p "$shadowsocks_config_dir"

    # Create Shadowsocks configuration file
    cat > "$shadowsocks_config_file" << EOF
{
    "server": "127.0.0.1",
    "server_port": ${SHADOWSOCKS_PORT},
    "password": "${SHADOWSOCKS_PASSWORD}",
    "timeout": 300,
    "method": "${SHADOWSOCKS_METHOD}",
    "fast_open": false,
    "mode": "tcp_only"
}
EOF

    # Set permissions to 644 so the DynamicUser in systemd can read it
    chmod 644 "$shadowsocks_config_file"
    chown root:root "$shadowsocks_config_file"

    # Create systemd service override if needed (for snap installations)
    local service_created=false
    if command -v snap &> /dev/null && snap list shadowsocks-libev &>/dev/null; then
        local snap_bin
        snap_bin=$(command -v snap)
        if [ -z "$snap_bin" ]; then
            snap_bin="/usr/bin/snap"
        fi

        # For snap installation: use config path inside snap's common dir (snap confinement)
        cat > /etc/systemd/system/shadowsocks-libev-server@config.service << EOF
[Unit]
Description=Shadowsocks-libev Server Service for %i
After=network.target

[Service]
Type=simple
ExecStart=${snap_bin} run shadowsocks-libev.ss-server -c ${shadowsocks_config_dir}/%i.json
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        service_created=true
    fi

    # Enable and start Shadowsocks service
    if [ "$service_created" = true ] || [ -f /etc/systemd/system/shadowsocks-libev-server@config.service ]; then
        systemctl enable shadowsocks-libev-server@config
        systemctl restart shadowsocks-libev-server@config
        if ! systemctl is-active --quiet shadowsocks-libev-server@config; then
            print_error "Shadowsocks service failed to start"
            print_status "Check logs with: journalctl -u shadowsocks-libev-server@config -n 50"
            exit 1
        fi
    elif systemctl list-unit-files | grep -q "shadowsocks-libev-server@.service"; then
        systemctl enable shadowsocks-libev-server@config
        systemctl restart shadowsocks-libev-server@config
        if ! systemctl is-active --quiet shadowsocks-libev-server@config; then
            print_error "Shadowsocks service failed to start"
            print_status "Check logs with: journalctl -u shadowsocks-libev-server@config -n 50"
            exit 1
        fi
    elif systemctl list-unit-files | grep -q "shadowsocks-libev.service"; then
        # Some distros use a different service name
        systemctl enable shadowsocks-libev
        systemctl restart shadowsocks-libev
        if ! systemctl is-active --quiet shadowsocks-libev; then
            print_error "Shadowsocks service failed to start"
            print_status "Check logs with: journalctl -u shadowsocks-libev -n 50"
            exit 1
        fi
    else
        print_error "Could not find Shadowsocks systemd service"
        exit 1
    fi

    print_status "Shadowsocks configured and started on port $SHADOWSOCKS_PORT"
    print_status "Encryption method: $SHADOWSOCKS_METHOD"
}

# Function to create systemd service
create_systemd_service() {
    print_status "Creating systemd service..."

    local service_name="dnstt-server"
    local service_file="${SYSTEMD_DIR}/${service_name}.service"
    local target_port

    case "$TUNNEL_MODE" in
        ssh)
            target_port=$(detect_ssh_port)
            print_status "Detected SSH port: $target_port"
            ;;
        shadowsocks)
            target_port="${SHADOWSOCKS_PORT:-8388}"
            print_status "Using Shadowsocks port: $target_port"
            ;;
        socks|*)
            target_port="1080"  # Dante SOCKS port
            ;;
    esac

    # Stop service if it's running to allow reconfiguration
    if systemctl is-active --quiet "$service_name"; then
        print_status "Stopping existing dnstt-server service for reconfiguration..."
        systemctl stop "$service_name"
    fi

    # Create systemd service file
    cat > "$service_file" << EOF
[Unit]
Description=dnstt DNS Tunnel Server
After=network.target
Wants=network.target

[Service]
Type=simple
User=$DNSTT_USER
Group=$DNSTT_USER
ExecStart=${INSTALL_DIR}/dnstt-server -udp :${DNSTT_PORT} -privkey-file ${PRIVATE_KEY_FILE} -mtu ${MTU_VALUE} ${DOMAIN} 127.0.0.1:${target_port}
Restart=always
RestartSec=5
KillMode=mixed
TimeoutStopSec=5

# Security settings
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadOnlyPaths=/
ReadWritePaths=${CONFIG_DIR}
PrivateTmp=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true

[Install]
WantedBy=multi-user.target
EOF

    # Reload systemd and enable service
    systemctl daemon-reload
    systemctl enable "$service_name"

    print_status "Systemd service created: $service_name"
    print_status "Service will run as user: $DNSTT_USER"
    print_status "Service will listen on port: $DNSTT_PORT (redirected from port 53)"
    print_status "Service will tunnel to 127.0.0.1:$target_port"
    print_status "Mode: $TUNNEL_MODE"
}

# Function to start services
start_services() {
    print_status "Starting services..."

    # Start dnstt-server service
    systemctl start dnstt-server

    print_status "dnstt-server service started"

    # Show service status
    systemctl status dnstt-server --no-pager -l
}

# Function to display final information
display_final_info() {
    print_success_box
}

# Function to remove iptables rules
remove_iptables_rules() {
    print_status "Removing iptables rules..."

    if ! command -v iptables &> /dev/null; then
        print_warning "iptables not found, skipping rule removal"
        return 0
    fi

    # Get the primary network interface
    local interface
    interface=$(ip route | grep default | awk '{print $5}' | head -1)
    if [[ -z "$interface" ]]; then
        interface=$(ip link show | grep -E "^[0-9]+: (eth|ens|enp)" | head -1 | cut -d':' -f2 | awk '{print $1}')
        if [[ -z "$interface" ]]; then
            interface="eth0"
        fi
    fi

    # Remove IPv4 rules
    print_status "Removing IPv4 iptables rules..."
    iptables -D INPUT -p udp --dport "$DNSTT_PORT" -j ACCEPT 2>/dev/null || true
    iptables -t nat -D PREROUTING -i "$interface" -p udp --dport 53 -j REDIRECT --to-ports "$DNSTT_PORT" 2>/dev/null || true

    # Remove IPv6 rules if available
    if command -v ip6tables &> /dev/null && [ -f /proc/net/if_inet6 ]; then
        print_status "Removing IPv6 iptables rules..."
        ip6tables -D INPUT -p udp --dport "$DNSTT_PORT" -j ACCEPT 2>/dev/null || true
        ip6tables -t nat -D PREROUTING -i "$interface" -p udp --dport 53 -j REDIRECT --to-ports "$DNSTT_PORT" 2>/dev/null || true
    fi

    # Save iptables rules after removal
    save_iptables_rules

    print_status "iptables rules removed"
}

# Function to remove firewall rules
remove_firewall_rules() {
    print_status "Removing firewall rules..."

    # Remove firewalld rules
    if command -v firewall-cmd &> /dev/null && systemctl is-active --quiet firewalld; then
        print_status "Removing firewalld rules..."
        firewall-cmd --permanent --remove-port="$DNSTT_PORT"/udp 2>/dev/null || true
        firewall-cmd --permanent --remove-port=53/udp 2>/dev/null || true
        firewall-cmd --reload 2>/dev/null || true
        print_status "Firewalld rules removed"
    fi

    # Remove ufw rules
    if command -v ufw &> /dev/null && ufw status | grep -q "Status: active"; then
        print_status "Removing ufw rules..."
        ufw delete allow "$DNSTT_PORT"/udp 2>/dev/null || true
        ufw delete allow 53/udp 2>/dev/null || true
        print_status "UFW rules removed"
    fi
}

# Function to uninstall dnstt
uninstall() {
    print_warning "This will completely remove dnstt from your system."
    print_question "Are you sure you want to uninstall? (y/N): "
    read -r confirm

    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        print_status "Uninstall cancelled."
        return 1
    fi

    print_status "Uninstalling dnstt..."

    # Stop and disable services
    print_status "Stopping services..."
    if systemctl is-active --quiet dnstt-server; then
        systemctl stop dnstt-server
        print_status "dnstt-server service stopped"
    fi

    if systemctl is-active --quiet danted; then
        systemctl stop danted
        print_status "Dante service stopped"
    fi

    if systemctl is-active --quiet shadowsocks-libev-server@config 2>/dev/null; then
        systemctl stop shadowsocks-libev-server@config
        print_status "Shadowsocks service stopped"
    fi

    # Disable services
    if systemctl is-enabled --quiet dnstt-server 2>/dev/null; then
        systemctl disable dnstt-server
        print_status "dnstt-server service disabled"
    fi

    if systemctl is-enabled --quiet danted 2>/dev/null; then
        systemctl disable danted
        print_status "Dante service disabled"
    fi

    if systemctl is-enabled --quiet shadowsocks-libev-server@config 2>/dev/null; then
        print_status "Disabling Shadowsocks service..."
        systemctl disable shadowsocks-libev-server@config
    fi

    # Remove Shadowsocks config if exists (both system and snap paths)
    if [ -f /etc/shadowsocks-libev/config.json ]; then
        print_status "Removing Shadowsocks configuration..."
        rm -f /etc/shadowsocks-libev/config.json
    fi
    if [ -f /var/snap/shadowsocks-libev/common/etc/shadowsocks-libev/config.json ]; then
        print_status "Removing Shadowsocks snap configuration..."
        rm -f /var/snap/shadowsocks-libev/common/etc/shadowsocks-libev/config.json
    fi

    # Remove systemd service files
    print_status "Removing systemd service files..."
    if [ -f "${SYSTEMD_DIR}/dnstt-server.service" ]; then
        rm -f "${SYSTEMD_DIR}/dnstt-server.service"
        systemctl daemon-reload
        print_status "Systemd service file removed"
    fi

    # Remove binaries
    print_status "Removing binaries..."
    if [ -f "${INSTALL_DIR}/dnstt-server" ]; then
        rm -f "${INSTALL_DIR}/dnstt-server"
        print_status "dnstt-server binary removed"
    fi

    # Remove configuration files
    print_status "Removing configuration files..."
    if [ -d "$CONFIG_DIR" ]; then
        rm -rf "$CONFIG_DIR"
        print_status "Configuration directory removed: $CONFIG_DIR"
    fi

    # Remove iptables rules
    remove_iptables_rules

    # Remove firewall rules
    remove_firewall_rules

    # Remove dnstt user
    print_status "Removing dnstt user..."
    if id "$DNSTT_USER" &>/dev/null; then
        userdel "$DNSTT_USER" 2>/dev/null || true
        print_status "User $DNSTT_USER removed"
    fi

    # Optionally remove dnstt-deploy script
    print_question "Do you want to remove the dnstt-deploy script itself? (y/N): "
    read -r remove_script
    if [[ "$remove_script" =~ ^[Yy]$ ]]; then
        if [ -f "$SCRIPT_INSTALL_PATH" ]; then
            rm -f "$SCRIPT_INSTALL_PATH"
            print_status "dnstt-deploy script removed from $SCRIPT_INSTALL_PATH"
        fi
    fi

    print_status "Uninstallation completed successfully!"

    return 0
}

# Main function
main() {
    # Check for uninstall argument
    if [ "$1" = "uninstall" ]; then
        uninstall
        exit 0
    fi

    # If not running from installed location (curl/GitHub), install the script first
    if [ "$0" != "$SCRIPT_INSTALL_PATH" ]; then
        print_status "Installing dnstt-deploy script..."
        install_script
        print_status "Starting dnstt server setup..."
    else
        # Running from installed location - check for updates and show menu
        check_for_updates
        handle_menu
        # If we reach here, user chose option 1 (Install/Reconfigure), so continue
        print_status "Starting dnstt server installation/reconfiguration..."
    fi

    # Detect OS and architecture
    detect_os
    detect_arch

    # Check and install required tools
    check_required_tools

    # Get user input
    get_user_input

    # Download and verify dnstt-server
    download_dnstt_server

    # Create dnstt user
    create_dnstt_user

    # Generate keys
    generate_keys

    # Save configuration after keys are generated
    save_config

    # Configure firewall and iptables
    configure_firewall

    # Setup tunnel mode specific configurations
    case "$TUNNEL_MODE" in
        socks)
            setup_dante
            # Stop Shadowsocks if it was running
            if systemctl is-active --quiet shadowsocks-libev-server@config 2>/dev/null; then
                print_status "Switching to SOCKS mode - stopping Shadowsocks service..."
                systemctl stop shadowsocks-libev-server@config
                systemctl disable shadowsocks-libev-server@config
            fi
            ;;
        shadowsocks)
            setup_shadowsocks
            # Stop Dante if it was running
            if systemctl is-active --quiet danted 2>/dev/null; then
                print_status "Switching to Shadowsocks mode - stopping Dante service..."
                systemctl stop danted
                systemctl disable danted
            fi
            ;;
        ssh|*)
            # If switching from SOCKS or Shadowsocks to SSH, stop those services
            if systemctl is-active --quiet danted 2>/dev/null; then
                print_status "Switching to SSH mode - stopping Dante service..."
                systemctl stop danted
                systemctl disable danted
            fi
            if systemctl is-active --quiet shadowsocks-libev-server@config 2>/dev/null; then
                print_status "Switching to SSH mode - stopping Shadowsocks service..."
                systemctl stop shadowsocks-libev-server@config
                systemctl disable shadowsocks-libev-server@config
            fi
            ;;
    esac

    # Create systemd service
    create_systemd_service

    # Start services
    start_services

    # Display final information
    display_final_info
}

# Run main function
main "$@"
