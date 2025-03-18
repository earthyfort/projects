import re
import email
import sys
from email import policy
from colorama import Fore, Style

# List of known suspicious domains often used in phishing
SUSPICIOUS_DOMAINS = [
    "bit.ly", "tinyurl.com", "paypal-security.com", "bank-login.com",
    "account-verification.com", "update-info.net"
]

# List of common phishing phrases
PHISHING_PHRASES = [
    "verify your account", "urgent action required", "login to update your information",
    "suspicious activity detected", "confirm your identity"
]

def parse_email(raw_email):
    """Parses raw email message and extracts useful information."""
    try:
        msg = email.message_from_string(raw_email, policy=policy.default)

        sender = msg["From"] or "Unknown"
        subject = msg["Subject"] or "No Subject"
        received_headers = msg.get_all("Received", [])  # Collect all Received headers
        spf_result = msg["Authentication-Results"] or "No SPF/DKIM"

        email_body = ""
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/plain":
                    email_body += part.get_payload(decode=True).decode(errors="ignore") + "\n"
        else:
            email_body = msg.get_payload(decode=True).decode(errors="ignore")

        return sender, subject, received_headers, spf_result, email_body
    except Exception as e:
        print(Fore.RED + f"Error parsing email: {e}" + Style.RESET_ALL)
        sys.exit(1)

def check_suspicious_links(text):
    """Finds suspicious links in the email text."""
    url_pattern = r"https?://[^\s]+"  
    found_urls = re.findall(url_pattern, text)

    flagged_urls = [url for url in found_urls if any(domain in url for domain in SUSPICIOUS_DOMAINS)]
    return flagged_urls

def check_phishing_phrases(text):
    """Checks for common phishing phrases."""
    detected_phrases = [phrase for phrase in PHISHING_PHRASES if phrase.lower() in text.lower()]
    return detected_phrases

def check_spoofed_email(sender):
    """Checks if the sender email contains suspicious domains."""
    email_pattern = r"[\w\.-]+@[\w\.-]+\.\w+"
    found_email = re.findall(email_pattern, sender)

    if found_email and any(domain in found_email[0] for domain in SUSPICIOUS_DOMAINS):
        return found_email[0]
    return None

def analyze_email(raw_email):
    """Analyzes an email for phishing indicators."""
    sender, subject, received_headers, spf_result, email_body = parse_email(raw_email)

    flagged_links = check_suspicious_links(email_body)
    detected_phrases = check_phishing_phrases(email_body)
    spoofed_email = check_spoofed_email(sender)

    risk_score = len(flagged_links) * 2 + len(detected_phrases) + (3 if spoofed_email else 0)

    print("\n" + Fore.YELLOW + "[ Phishing Email Analysis ]" + Style.RESET_ALL)
    print(Fore.CYAN + f"From: {sender}" + Style.RESET_ALL)
    print(Fore.CYAN + f"Subject: {subject}" + Style.RESET_ALL)

    if spoofed_email:
        print(Fore.RED + "⚠ Suspicious Sender Email Detected:" + Style.RESET_ALL)
        print(f"   - {spoofed_email}")

    if flagged_links:
        print(Fore.RED + "⚠ Suspicious Links Found:" + Style.RESET_ALL)
        for link in flagged_links:
            print(f"   - {link}")

    if detected_phrases:
        print(Fore.RED + "⚠ Common Phishing Phrases Detected:" + Style.RESET_ALL)
        for phrase in detected_phrases:
            print(f"   - {phrase}")

    print(Fore.BLUE + "\n[ Email Routing Information ]" + Style.RESET_ALL)
    if received_headers:
        for i, header in enumerate(received_headers, start=1):
            print(f"   {i}. {header.strip()}")

    print(Fore.MAGENTA + f"\nSPF/DKIM Result: {spf_result}" + Style.RESET_ALL)

    print("\n" + Fore.CYAN + f"Overall Risk Score: {risk_score}/10" + Style.RESET_ALL)
    
    if risk_score > 5:
        print(Fore.RED + "🚨 This email is highly suspicious!" + Style.RESET_ALL)
    else:
        print(Fore.GREEN + "✅ No major phishing indicators detected." + Style.RESET_ALL)

def main():
    print(Fore.BLUE + "\n[ Phishing Email Detector ]" + Style.RESET_ALL)
    print(Fore.YELLOW + "Paste the full email source (headers + body), then type 'END' on a new line and press Enter:\n" + Style.RESET_ALL)
    
    # Read multiline input until user types "END"
    lines = []
    while True:
        try:
            line = input()
            if line.strip().upper() == "END":
                break
            lines.append(line)
        except EOFError:
            break
    raw_email = "\n".join(lines)

    if not raw_email.strip():
        print(Fore.RED + "Error: No email content provided. Please try again." + Style.RESET_ALL)
        return

    analyze_email(raw_email)

if __name__ == "__main__":
    main()
