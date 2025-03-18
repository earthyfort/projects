import requests

# Set your VirusTotal API Key here
VIRUSTOTAL_API_KEY = "your_virustotal_api_key"

def check_virustotal(value):
    """Checks VirusTotal for IP address, domain, or file hash"""
    url = f"https://www.virustotal.com/api/v3/search?query={value}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        data = response.json()
        results = data.get("data", [])
        if results:
            positives = results[0]["attributes"]["last_analysis_stats"]["malicious"]
            return f"VirusTotal: {positives} detections"
        else:
            return "VirusTotal: No results found"
    else:
        return f"Error with VirusTotal: {response.status_code}"

def main():
    value = input("Enter an IP, domain, or file hash: ").strip()
    
    vt_result = check_virustotal(value)
    
    print("\n[ Threat Intelligence Lookup Results ]")
    print(vt_result)

if __name__ == "__main__":
    main()
