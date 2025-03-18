import json
import subprocess
import xml.etree.ElementTree as ET

# Event log categories to monitor
LOG_NAMES = ["Security", "Microsoft-Windows-Sysmon/Operational"]

# Sysmon & Security Event IDs of interest
EVENT_IDS = {
    "Sysmon": [1, 3, 8, 10, 11, 13, 22],  # Process Create, Network Connect, etc.
    "Security": [4624, 4625, 4688, 4697]  # Logins, Process Creation, New Services
}

def get_windows_event_logs(log_name, max_events=50):
    """Fetches Windows Event Logs and returns as XML"""
    try:
        command = f'wevtutil qe {log_name} /f:xml /c:{max_events}'
        output = subprocess.run(command, capture_output=True, text=True, shell=True)
        return output.stdout
    except Exception as e:
        print(f"Error retrieving logs: {e}")
        return None

def parse_event_logs(xml_logs):
    """Parses XML logs and extracts event details"""
    logs = []
    root = ET.fromstring(f"<Events>{xml_logs}</Events>")  # Wrap in <Events> for parsing

    for event in root.findall("Event"):
        event_id = event.find("./System/EventID").text
        event_time = event.find("./System/TimeCreated").attrib["SystemTime"]
        event_data = {}

        for data in event.findall(".//Data"):
            name = data.attrib.get("Name", "Unknown")
            event_data[name] = data.text

        logs.append({
            "EventID": int(event_id),
            "Timestamp": event_time,
            "Details": event_data
        })

    return logs

def filter_relevant_logs(logs):
    """Filters logs to include only relevant Sysmon/Security event IDs"""
    return [log for log in logs if log["EventID"] in EVENT_IDS["Sysmon"] + EVENT_IDS["Security"]]

def save_logs_to_json(logs, filename="parsed_logs.json"):
    """Saves logs to a JSON file"""
    with open(filename, "w") as f:
        json.dump(logs, f, indent=4)
    print(f"✅ Logs saved to {filename}")

def main():
    all_logs = []

    for log_name in LOG_NAMES:
        print(f"🔍 Retrieving {log_name} logs...")
        xml_logs = get_windows_event_logs(log_name)
        if xml_logs:
            parsed_logs = parse_event_logs(xml_logs)
            filtered_logs = filter_relevant_logs(parsed_logs)
            all_logs.extend(filtered_logs)

    if all_logs:
        print(f"✅ Found {len(all_logs)} relevant security events.")
        save_logs_to_json(all_logs)
    else:
        print("⚠ No relevant security events found.")

if __name__ == "__main__":
    main()
