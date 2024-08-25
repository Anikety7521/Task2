#!/bin/bash

# Define colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Generate timestamp
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# Report files with timestamp
REPORT_FILE="/tmp/security_audit_report_$TIMESTAMP.txt"
SUMMARY_FILE="/tmp/security_audit_summary_$TIMESTAMP.txt"


# Logging function
log() {
    local level="$1"
    local message="$2"
    case $level in
        INFO) echo -e "${GREEN}[INFO] ${message}${NC}" ;;
        WARNING) echo -e "${YELLOW}[WARNING] ${message}${NC}" ;;
        ERROR) echo -e "${RED}[ERROR] ${message}${NC}" ;;
        *) echo -e "[UNKNOWN] ${message}" ;;
    esac
    echo "[$level] $message" >> "$REPORT_FILE"
    echo "$message" >> "$SUMMARY_FILE"
}

# Detect OS
detect_os() {
    echo -e "${BLUE}==== Detecting OS ====${NC}"
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        VERSION=$VERSION_ID
    else
        log ERROR "Unable to detect OS. Exiting."
        exit 1
    fi
    log INFO "Detected OS: $OS $VERSION"
}

# Install necessary packages based on the OS
install_packages() {
    echo -e "${BLUE}==== Installing Packages ====${NC}"
    case $OS in
        ubuntu|debian)
            log INFO "Installing required packages for Ubuntu/Debian..."
            sudo apt-get update
            echo
            sudo apt-get install -y grub2-common iptables ufw firewalld net-tools curl
            ;;
        rhel|centos|fedora)
            log INFO "Installing required packages for RHEL/CentOS/Fedora..."
            sudo yum install -y grub2-tools iptables-services net-tools curl
            echo
            sudo dnf install -y grub2-tools iptables-services net-tools curl
            ;;
        *)
            log WARNING "Unsupported OS: $OS. Unable to install necessary packages."
            ;;
    esac
}

# 1. User and Group Audits
user_group_audit() {
    echo -e "${CYAN}==== User and Group Audit ====${NC}"
    log INFO "Starting user and group audit..."

    log INFO "Listing all users and groups..."
    echo
    cut -d: -f1 /etc/passwd >> "$REPORT_FILE"
    echo
    cut -d: -f1 /etc/group >> "$REPORT_FILE"

    log INFO "Checking for users with UID 0..."
    echo
    awk -F: '$3 == 0 {print $1}' /etc/passwd >> "$REPORT_FILE"

    log INFO "Checking for users without passwords..."
    echo
    awk -F: '($2 == "" || $2 == "x") {print $1}' /etc/shadow >> "$REPORT_FILE"
}

# 2. File and Directory Permissions
file_permissions() {
    echo -e "${CYAN}==== File and Directory Permissions ====${NC}"
    log INFO "Scanning for world-writable files and directories..."
    echo
    find / -xdev -type f -perm -022 2>/dev/null -exec ls -l {} \; >> "$REPORT_FILE"

    log INFO "Checking SSH directory permissions..."
    echo
    ls -ld /etc/ssh /root/.ssh /home/*/.ssh 2>/dev/null >> "$REPORT_FILE"

    log INFO "Reporting SUID/SGID bits set..."
    echo
    find / -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null -exec ls -l {} \; >> "$REPORT_FILE"
}

# 3. Service Audits
service_audit() {
    echo -e "${CYAN}==== Service Audits ====${NC}"
    log INFO "Listing all running services..."
    echo
    systemctl list-units --type=service --state=running >> "$REPORT_FILE"

    log INFO "Checking for unauthorized services..."
    echo
    for service in apache2 telnet vsftpd; do
        if systemctl is-active --quiet $service; then
            log WARNING "$service is running and may be unauthorized"
        else
            log INFO "$service is not running"
        fi
    done
}

# 4. Firewall and Network Security
firewall_security() {
    echo -e "${CYAN}==== Firewall and Network Security ====${NC}"
    log INFO "Checking if firewall is active..."
    echo
    if command -v ufw > /dev/null; then
        ufw status >> "$REPORT_FILE"
    elif command -v iptables > /dev/null; then
        iptables -L >> "$REPORT_FILE"
    elif command -v firewall-cmd > /dev/null; then
        firewall-cmd --list-all >> "$REPORT_FILE"
    else
        log WARNING "No firewall found"
    fi

    log INFO "Reporting open ports..."
    echo
    netstat -tuln >> "$REPORT_FILE"
}

# 5. IP and Network Configuration Checks
ip_network_checks() {
    echo -e "${CYAN}==== IP and Network Configuration Checks ====${NC}"
    log INFO "Identifying public vs. private IPs..."
    echo

    # Fetch public IP
    public_ip=$(curl -s ifconfig.me)
    if [ $? -eq 0 ]; then
        log INFO "Public IP: $public_ip"
    else
        log WARNING "Unable to retrieve public IP address."
    fi

    # Check private IPs
    for ip in $(hostname -I); do
        if [[ $ip =~ ^10\. ]] || [[ $ip =~ ^192\.168\. ]] || [[ $ip =~ ^172\.(1[6-9]|2[0-9]|3[01])\. ]]; then
            log INFO "Private IP: $ip"
        else
            log INFO "Public IP: $ip"
        fi
    done
}

# 6. Security Updates and Patching
security_updates() {
    echo -e "${CYAN}==== Security Updates and Patching ====${NC}"
    log INFO "Checking for available security updates..."
    echo
    if command -v apt-get > /dev/null; then
        apt-get update
        echo
        apt-get --just-print upgrade >> "$REPORT_FILE"
    elif command -v yum > /dev/null; then
        yum check-update >> "$REPORT_FILE"
    elif command -v dnf > /dev/null; then
        dnf check-update >> "$REPORT_FILE"
    else
        log WARNING "No package manager found"
    fi
}

# 7. Log Monitoring
log_monitoring() {
    echo -e "${CYAN}==== Log Monitoring ====${NC}"
    log INFO "Checking for suspicious log entries..."
    echo
    if [ -f /var/log/auth.log ]; then
        grep 'Failed password' /var/log/auth.log | tail -n 10 >> "$REPORT_FILE" 2>/dev/null
    elif [ -f /var/log/secure ]; then
        grep 'Failed password' /var/log/secure | tail -n 10 >> "$REPORT_FILE" 2>/dev/null
    else
        log WARNING "Authentication log not found"
    fi
}

# 8. Server Hardening Steps
server_hardening() {
    echo -e "${CYAN}==== Server Hardening Steps ====${NC}"
    log INFO "Implementing SSH key-based authentication and disabling password login for root..."

    # Backup the current sshd_config before making changes
    echo
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak

    # Disable password authentication and root login in sshd_config
    echo
    if grep -q '^#PasswordAuthentication' /etc/ssh/sshd_config; then
        sed -i 's/^#PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
    else
        sed -i '/^PasswordAuthentication /d' /etc/ssh/sshd_config
        echo 'PasswordAuthentication no' >> /etc/ssh/sshd_config
    fi

    if grep -q '^#PermitRootLogin' /etc/ssh/sshd_config; then
        sed -i 's/^#PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
    else
        sed -i '/^PermitRootLogin /d' /etc/ssh/sshd_config
        echo 'PermitRootLogin prohibit-password' >> /etc/ssh/sshd_config
    fi

    # Check if the settings were applied
    echo
    grep '^PasswordAuthentication no' /etc/ssh/sshd_config > /dev/null
    if [ $? -eq 0 ]; then
        log INFO "PasswordAuthentication set to no"
    else
        log WARNING "Failed to set PasswordAuthentication to no"
    fi

    grep '^PermitRootLogin prohibit-password' /etc/ssh/sshd_config > /dev/null
    if [ $? -eq 0 ]; then
        log INFO "PermitRootLogin set to prohibit-password"
    else
        log WARNING "Failed to set PermitRootLogin to prohibit-password"
    fi

    # Reload SSH daemon to apply changes
    echo
    systemctl reload sshd

    log INFO "Disabling IPv6 if not required..."
    echo
    sysctl -w net.ipv6.conf.all.disable_ipv6=1
    sysctl -w net.ipv6.conf.default.disable_ipv6=1
    echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
    echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf

    log INFO "Securing the GRUB bootloader..."
    echo
    if [ -f /etc/grub.d/00_header ]; then
        # Check if grub-mkpasswd-pbkdf2 is available
        if command -v grub-mkpasswd-pbkdf2 > /dev/null; then
            # Prompt user for GRUB password
            read -sp "Enter GRUB password: " grub_password
            echo
            read -sp "Re-enter GRUB password: " grub_password_confirm
            echo

            if [ "$grub_password" != "$grub_password_confirm" ]; then
                log ERROR "Passwords do not match. Exiting."
                exit 1
            fi

            # Generate password hash
            password_hash=$(echo "$grub_password" | grub-mkpasswd-pbkdf2 | grep -oP '(?<=is ).*')

            # Update GRUB configuration
            echo "set superusers=\"root\"" >> /etc/grub.d/00_header
            echo "password_pbkdf2 root $password_hash" >> /etc/grub.d/00_header
            update-grub
        else
            log WARNING "grub-mkpasswd-pbkdf2 not found. Unable to secure GRUB bootloader."
        fi
    else
        log WARNING "GRUB configuration file /etc/grub.d/00_header not found."
    fi

    log INFO "Configuring iptables/firewalld firewall rules..."
    echo
    if command -v iptables > /dev/null; then
        iptables -P INPUT DROP
        iptables -P FORWARD DROP
        iptables -P OUTPUT ACCEPT
        iptables -A INPUT -i lo -j ACCEPT
        iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
        iptables -A INPUT -p tcp --dport 22 -j ACCEPT
        mkdir -p /etc/iptables
        iptables-save > /etc/iptables/rules.v4
    elif command -v firewall-cmd > /dev/null; then
        firewall-cmd --permanent --add-port=22/tcp
        firewall-cmd --reload
    fi
}
# 9. Custom Security Checks
custom_checks() {
    log INFO "Loading custom security checks..."
    if [ -f /etc/security/custom_checks.conf ]; then
        source /etc/security/custom_checks.conf
    else
        log WARNING "Custom security checks file not found"
    fi
}
# 11. Reporting and Alerting
reporting_and_alerting() {
    log INFO "Generated report mailing..."
    

    if [ -s "$SUMMARY_FILE" ]; then
        log WARNING "Critical issues found during the audit. Sending email alert..."
        # Send an email (assuming mail command is available)
        mail -s "Security Audit Report" admin@example.com < "$SUMMARY_FILE"
    fi
}

# Main script execution
log INFO "Starting security audit..."

# Call functions
detect_os
install_packages
user_group_audit
file_permissions
service_audit
firewall_security
ip_network_checks
security_updates
log_monitoring
server_hardening
reporting_and_alerting

# Final summary
log INFO "Security audit completed. Report saved to $REPORT_FILE."
log INFO "Summary report saved to $SUMMARY_FILE."

