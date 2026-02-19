import json
import re
import requests
from openai import OpenAI
import os

client = OpenAI()

# -------------------------
# Helper: Internal IP Check
# -------------------------
def is_internal_ip(ip):
    if not ip:
        return False

    private_prefixes = (
        "10.",
        "192.168.",
        "172.16.", "172.17.", "172.18.", "172.19.",
        "172.20.", "172.21.", "172.22.", "172.23.",
        "172.24.", "172.25.", "172.26.", "172.27.",
        "172.28.", "172.29.", "172.30.", "172.31."
    )

    return ip.startswith(private_prefixes)

# -------------------------
# AI Enrichment Layer
# -------------------------
def generate_ai_analysis(alert):
    try:
        prompt = f"""
You are a senior SOC Tier-2 analyst.

Analyze this security alert and provide:

1. Technical Summary
2. Why this is suspicious
3. Investigation Steps
4. Containment Recommendations

Alert Data:
Process: {alert['process']}
Parent: {alert['parent']}
Command: {alert['command']}
Network Activity: {alert['network_activity']}
Destination IP: {alert['destination_ip']}
Risk Score: {alert['risk_score']}
MITRE Techniques: {', '.join(alert['mitre_techniques'])}
"""

        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.2
        )

        return response.choices[0].message.content

    except Exception:
        return """
AI Fallback Analysis:

Technical Summary:
Suspicious PowerShell execution with outbound network activity detected.

Why Suspicious:
PowerShell is frequently abused for post-exploitation.
External network communication increases likelihood of command-and-control behavior.

Investigation Steps:
- Review full process tree
- Inspect command-line parameters
- Check persistence mechanisms
- Search environment for similar activity

Containment:
- Isolate host
- Block suspicious outbound IP
- Reset potentially compromised credentials
"""

# -------------------------
# Send Alert to Splunk HEC
# -------------------------
def send_to_splunk(alert):
    splunk_hec_url = "https://localhost:8088/services/collector"
    splunk_token = os.getenv("SPLUNK_HEC_TOKEN")

    headers = {
        "Authorization": f"Splunk {splunk_token}"
    }

    payload = {
        "event": alert,
        "sourcetype": "ai_soc_alert",
        "index": "main"
    }

    try:
        response = requests.post(
            splunk_hec_url,
            headers=headers,
            json=payload,
            verify=False  # Ignore SSL cert in lab
        )

        if response.status_code == 200:
            print("✔ Sent alert to Splunk")
        else:
            print("✖ Failed to send to Splunk:", response.text)

    except Exception as e:
        print("Error sending to Splunk:", str(e))

# -------------------------
# Core Detection Engine
# -------------------------
def run_engine():

    with open("sysmon_filtered.json", "r", encoding="utf-16") as f:
        data = json.load(f)

    if not isinstance(data, list):
        data = [data]

    events = {}

    # ---- Correlation Phase ----
    for event in data:
        message = event.get("Message", "")
        event_id = event.get("Id")

        process = re.search(r"Image:\s+(.*)", message)
        parent = re.search(r"ParentImage:\s+(.*)", message)
        command = re.search(r"CommandLine:\s+(.*)", message)
        dest_ip = re.search(r"DestinationIp:\s+(.*)", message)

        process_name = process.group(1).strip() if process else None
        parent_name = parent.group(1).strip() if parent else None
        command_line = command.group(1).strip() if command else None
        destination_ip = dest_ip.group(1).strip() if dest_ip else None

        if process_name:
            if process_name not in events:
                events[process_name] = {
                    "parent": parent_name,
                    "command": command_line,
                    "network": False,
                    "destination_ip": None
                }

            if event_id == 3 and destination_ip:
                events[process_name]["network"] = True
                events[process_name]["destination_ip"] = destination_ip

    alerts = []

    # ---- Risk Scoring Phase ----
    for process, details in events.items():
        risk = 0
        techniques = []

        if "powershell" in process.lower():
            risk += 5
            techniques.append("T1059 - Command and Scripting Interpreter")

        if details["network"]:
            risk += 2
            techniques.append("T1071 - Application Layer Protocol")

        if details["destination_ip"] and not is_internal_ip(details["destination_ip"]):
            risk += 2

        if details["parent"] and "winword.exe" in details["parent"].lower():
            risk += 3
            techniques.append("T1204 - User Execution")

        suspicious_flags = [
            "-executionpolicy bypass",
            "encodedcommand",
            "iex",
            "downloadstring"
        ]

        if details["command"]:
            for flag in suspicious_flags:
                if flag in details["command"].lower():
                    risk += 2
                    break

        if risk >= 7:
            alert = {
                "process": process,
                "parent": details["parent"],
                "command": details["command"],
                "network_activity": details["network"],
                "destination_ip": details["destination_ip"],
                "risk_score": risk,
                "severity": "High" if risk >= 9 else "Medium",
                "mitre_techniques": techniques
            }

            alert["ai_analysis"] = generate_ai_analysis(alert)

            send_to_splunk(alert)

            alerts.append(alert)

    return alerts
