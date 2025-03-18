import re
import sys
import os
from collections import defaultdict
from datetime import datetime
from colorama import Fore, Style

# Define log file location (adjust based on your OS)
LOG_FILE = "/var/log/auth.log"  # Ubuntu/Debian
# LOG_FILE = "/var/log/secure"  # CentOS/RHEL

# Set detection threshold
FAILED_ATTEMPTS_THRESHOLD = 5

def parse_ssh_logs():
    """Parses SSH logs to detect brute-force attacks."""
    if not os.path.exists(LOG_FILE):
        print(Fore.RED + f"Error: Log file '{LOG_FILE}' not found!" + Style.RESET_ALL)
        sys.exit(1)

    failed_attempts = defaultdict(int)
    attack_timestamps = defaultdict(list)

    with open(LOG_FILE, "r") as file:
        for line in file:
            # Match failed SSH login attempts
            match = re.search(r"Failed password for .* from (\d+\.\d+\.\d+\.\d+)", line)
            if match:
                ip = match.group(1)
                failed_attempts[ip] += 1
                attack_timestamps[ip].append(line.split()[0:3])  # Extract date/time info

    return failed_attempts, attack_timestamps

def detect_brute_force(failed_attempts, attack_timestamps):
    """Detects brute-force attempts based on threshold."""
    print(Fore.YELLOW + "[ SSH Brute-Force Detection ]" + Style.RESET_ALL)
    suspicious_ips = {ip: count for ip, count in failed_attempts.items() if count >= FAILED_ATTEMPTS_THRESHOLD}

    if not suspicious_ips:
        print(Fore.GREEN + "✅ No brute-force attacks detected." + Style.RESET_ALL)
        return

    for ip, count in suspicious_ips.items():
        print(Fore.RED + f"⚠ Suspicious Activity Detected from IP: {ip}" + Style.RESET_ALL)
        print(f"   - Failed Attempts: {count}")
        print(f"   - Attack Timestamps: {', '.join([' '.join(time) for time in attack_timestamps[ip]])}")

        action = input(Fore.CYAN + "🚨 Block this IP using iptables? (yes/no): " + Style.RESET_ALL).strip().lower()
        if action == "yes":
            block_ip(ip)

def block_ip(ip):
    """Blocks an IP address using iptables."""
    command = f"sudo iptables -A INPUT -s {ip} -j DROP"
    os.system(command)
    print(Fore.RED + f"🚫 IP {ip} has been blocked." + Style.RESET_ALL)

def main():
    failed_attempts, attack_timestamps = parse_ssh_logs()
    detect_brute_force(failed_attempts, attack_timestamps)

if __name__ == "__main__":
    main()
