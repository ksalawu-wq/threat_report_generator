import os
import re
from scapy.all import rdpcap, TCP, IP
import datetime
from collections import defaultdict

def save_uploaded_file(uploaded_file):
    upload_dir = "uploads"
    os.makedirs(upload_dir, exist_ok=True)
    filepath = os.path.join(upload_dir, uploaded_file.name)
    with open(filepath, "wb") as f:
        f.write(uploaded_file.read())
    return filepath

def parse_pcap(file_path):
    packets = rdpcap(file_path)
    events = []
    c2_candidates = defaultdict(int)
    src_counter = defaultdict(int)
    first_host = None

    for pkt in packets:
        try:
            if IP in pkt and TCP in pkt:
                timestamp = datetime.datetime.fromtimestamp(float(pkt.time))
                src = pkt[IP].src
                dst = pkt[IP].dst
                sport = pkt[TCP].sport
                dport = pkt[TCP].dport

                event = f"{timestamp} - TCP from {src}:{sport} to {dst}:{dport}"
                events.append(event)

                key = f"{src} -> {dst}:{dport}"
                c2_candidates[key] += 1

                src_counter[src] += 1
                if not first_host:
                    first_host = src

        except Exception as e:
            print("Error decoding packet:", e)

    metadata = {
        "c2_candidates": c2_candidates,
        "initial_host": first_host
    }
    return "\n".join(events), metadata

def parse_log_file(file_path, is_pcap=False):
    if is_pcap:
        return parse_pcap(file_path)
    else:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            text = f.read()
        metadata = {
            "c2_candidates": {},
            "initial_host": None
        }
        return text, metadata

def generate_report(log_text, metadata=None):
    import re

    if isinstance(log_text, tuple):
        log_text = log_text[0]

    lines = log_text.splitlines()
    iocs = set()
    timeline = []
    c2_patterns = []
    compromise_details = []
    compromise_analysis = []

    ip_port_pattern = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})(?::(\d{1,5}))?")
    url_pattern = re.compile(r"https?://[^\s]+")

    dst_ip_count = {}

    for line in lines:
        matches = ip_port_pattern.findall(line)
        urls = url_pattern.findall(line)

        if matches:
            for ip, port in matches:
                ioc_entry = f"{ip}:{port}" if port else ip
                iocs.add(ioc_entry)

                # Count destination IPs for C2 pattern detection
                dst_ip_count[ip] = dst_ip_count.get(ip, 0) + 1

            timeline.append(line)

        if urls:
            iocs.update(urls)
            timeline.append(line)

        # Basic C2 heuristic: known suspicious ports
        if any(port in ['4444', '8080', '1337'] for _, port in matches if port):
            c2_patterns.append(line)

        # Initial compromise indicators
        if any(keyword in line.lower() for keyword in ["exploit", "download", "malware", "payload", "infected", "executed"]):
            compromise_details.append(line)

    # C2 heuristic: repeated communication to same IP
    for ip, count in dst_ip_count.items():
        if count > 5:
            c2_patterns.append(f"Possible beaconing behavior: {ip} contacted {count} times.")

    # Compromise analysis summary
    if compromise_details:
        for entry in compromise_details:
            if "download" in entry.lower():
                compromise_analysis.append("Suspicious download observed — likely delivery of payload.")
            if "exploit" in entry.lower():
                compromise_analysis.append("Exploit activity detected — potential vulnerability leveraged.")
            if "executed" in entry.lower():
                compromise_analysis.append("Execution of code indicates successful compromise.")
    else:
        compromise_analysis.append("No strong evidence of compromise detected from keywords.")

    executive_summary = (
        f"The uploaded log file contains {len(lines)} entries. "
        f"A total of {len(iocs)} IOCs were found, including suspicious IPs, ports, and URLs. "
        f"Timeline, C2 communication, and compromise indicators are outlined below."
    )

    remediation = [
        "Review the highlighted IOCs for malicious endpoints.",
        "Block listed IPs/ports in perimeter firewalls.",
        "Check affected hosts for malware indicators.",
        "Patch software vulnerabilities noted in logs.",
        "Monitor logs for similar behavior in the future."
    ]

    return {
        "executive_summary": executive_summary,
        "iocs": sorted(iocs),
        "timeline": "\n".join(timeline),
        "remediation": remediation,
        "c2_traffic": "\n".join(c2_patterns) or "No clear C2 patterns detected.",
        "initial_compromise": "\n".join(compromise_details) or "No obvious initial compromise found.",
        "compromise_analysis": "\n".join(set(compromise_analysis))
    }
