import json
import random
from pathlib import Path


KNOWN_MALICIOUS_IPS = [
    "185.220.101.45",
    "45.133.1.10"
]

KNOWN_MALICIOUS_DOMAINS = [
    "1.example-domains.com",
    "2.example-domains.net"
]


MITRE_MAPPING = {
    "ioc_detection": {
        "technique": "T1071",
        "name": "Application Layer Protocol"
    }
}


def generate_fake_logs():

    print("[INFO] Generating simulated network logs...")

    logs = []

    normal_domains = [
        "1.exapmle.com",
        "2.example.com",
        "3.example.com"
    ]

    normal_ips = [
        "8.8.8.8",
        "1.1.1.1",
        "142.250.190.14"
    ]

    for _ in range(5):

        logs.append({
            "hostname": f"WS-{random.randint(10,99)}",
            "destination_ip": random.choice(normal_ips),
            "domain": random.choice(normal_domains)
        })

    logs.append({
        "hostname": "WIN10-LAB",
        "destination_ip": random.choice(KNOWN_MALICIOUS_IPS),
        "domain": random.choice(KNOWN_MALICIOUS_DOMAINS)
    })

    return logs


def detect_iocs(logs):

    alerts = []

    for log in logs:

        ip = log["destination_ip"]
        domain = log["domain"]

        malicious_ip = ip in KNOWN_MALICIOUS_IPS
        malicious_domain = domain in KNOWN_MALICIOUS_DOMAINS

        if malicious_ip or malicious_domain:

            alerts.append({
                "title": "Malicious IOC Communication Detected",
                "severity": "HIGH",
                "hostname": log["hostname"],
                "destination_ip": ip,
                "domain": domain,
                "technique": MITRE_MAPPING["ioc_detection"]["technique"],
                "technique_name": MITRE_MAPPING["ioc_detection"]["name"]
            })

    return alerts


def enrich_ioc(alert):

    print("\n[SOAR] IOC Enrichment Started")
    print("[THREAT INTEL] Reputation Score: MALICIOUS")
    print("[THREAT INTEL] Confidence: HIGH")


def isolate_host(hostname):

    print(f"[SOAR] Host isolation queued: {hostname}")


def notify_slack(alert):

    print(f"[SLACK] Alert notification sent for {alert['hostname']}")


def run_pipeline():

    logs = generate_fake_logs()

    print("[INFO] Running detection pipeline...")

    alerts = detect_iocs(logs)

    if not alerts:
        print("[INFO] No malicious activity detected")
        return

    for alert in alerts:

        print("\n========== ALERT ==========")
        print(f"Title         : {alert['title']}")
        print(f"Severity      : {alert['severity']}")
        print(f"Hostname      : {alert['hostname']}")
        print(f"DestinationIP : {alert['destination_ip']}")
        print(f"Domain        : {alert['domain']}")
        print(f"Technique     : {alert['technique']}")
        print(f"ATT&CK        : {alert['technique_name']}")

        enrich_ioc(alert)
        isolate_host(alert["hostname"])
        notify_slack(alert)


if __name__ == "__main__":

    run_pipeline()
