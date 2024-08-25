# Task2

# Security Audit Script

This script performs a comprehensive security audit on Linux systems, including OS detection, package installation, user and group audits, file and directory permissions checks, service audits, firewall and network security checks, and server hardening.

## Installation

1. **Clone the repository:**
   ```bash
   git clone <repository-url>
   cd <repository-directory>

## Ensure you have required dependencies:

mail command for sending emails. Install with
sudo apt-get install mailutils # For Ubuntu/Debian
sudo yum install mailx # For RHEL/CentOS
## Make the script executable:
chmod +x security_audit.sh


## Configuration
Custom Security Checks: If you have custom security checks, create a file named /etc/security/custom_checks.conf and add your custom checks in this file.

Usage
To run the security audit script:

Execute the script:
sudo ./security_audit.sh

## Review Reports:

The full audit report will be saved to /tmp/security_audit_report_<timestamp>.txt.
A summary of critical issues will be saved to /tmp/security_audit_summary_<timestamp>.txt.
Email Alerts: If critical issues are found, an email alert will be sent to the configured recipient.

## Example Configuration Files
Custom Security Checks (/etc/security/custom_checks.conf)
You can define additional security checks in this file. Here's an example format:

# Example Custom Security Check
log INFO "Performing custom security check..."

# Check for certain files
if [ -f /etc/security/some_important_file ]; then
    log INFO "Important file found."
else
    log WARNING "Important file not found."
fi



