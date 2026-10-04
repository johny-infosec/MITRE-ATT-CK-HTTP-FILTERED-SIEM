import sys
import os
import subprocess
import yaml

def extract_keywords_from_detection(detection_block):
    """Helper to pull searchable string keywords out of a Sigma rule's detection block."""
    keywords = []
    if not isinstance(detection_block, dict):
        return keywords

    for key, val in detection_block.items():
        if isinstance(val, str):
            keywords.append(val.lower())
        elif isinstance(val, list):
            for item in val:
                if isinstance(item, str):
                    keywords.append(item.lower())
        elif isinstance(val, dict):
            keywords.extend(extract_keywords_from_detection(val))
    return keywords

def load_sigma_rules(rules_dir):
    rules = []
    # Log sources that indicate network traffic rather than endpoint process execution
    valid_log_sources = ['webserver', 'proxy', 'zeek', 'firewall', 'dns', 'packet', 'http']

    print(f"[*] Scanning '{rules_dir}' for Network & Web Sigma rules...")
    for root, dirs, files in os.walk(rules_dir):
        for file in files:
            if file.endswith(('.yml', '.yaml')):
                path = os.path.join(root, file)
                try:
                    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                        data = yaml.safe_load(f)
                        if data and isinstance(data, dict):
                            title = data.get('title', 'Unknown Rule')
                            logsource = data.get('logsource', {})
                            service = str(logsource.get('service', '')).lower()
                            category = str(logsource.get('category', '')).lower()
                            product = str(logsource.get('product', '')).lower()

                            # Ensure the rule is actually meant for network/web traffic
                            is_network_rule = any(v in service or v in category or v in product for v in valid_log_sources)

                            if is_network_rule:
                                tags = data.get('tags', [])
                                detection = data.get('detection', {})
                                keywords = extract_keywords_from_detection(detection)

                                # Filter out short keywords (< 4 chars) to prevent false positives on common URL chunks
                                valid_keywords = [kw for kw in keywords if len(kw) > 3]

                                if any(str(t).startswith('attack.') for t in tags) and valid_keywords:
                                    rules.append({
                                        'title': title,
                                        'tags': tags,
                                        'keywords': valid_keywords
                                    })
                except Exception:
                    continue

    print(f"[+] Successfully loaded network rules (Total active: {len(rules)}).")
    return rules

def analyze_pcap(pcap_file, rules):
    if not os.path.exists(pcap_file):
        print(f"[!] Error: PCAP file '{pcap_file}' not found.")
        return

    print(f"[*] Analyzing '{pcap_file}' using tshark...")
    cmd = [
        "tshark", "-r", pcap_file,
        "-Y", "http",
        "-T", "fields",
        "-e", "ip.src",
        "-e", "http.host",
        "-e", "http.request.uri",
        "-e", "http.user_agent"
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        lines = result.stdout.strip().split('\n')
    except subprocess.CalledProcessError as e:
        print(f"[!] Error running tshark: {e}")
        return

    print(f"[*] Scanning packets against {len(rules)} loaded network rules...\n")

    alert_count = 0
    packet_count = 0

    for line in lines:
        if not line.strip():
            continue
        packet_count += 1
        parts = line.split('\t')
        src_ip = parts[0] if len(parts) > 0 and parts[0] else "Unknown"
        host = parts[1] if len(parts) > 1 and parts[1] else ""
        uri = parts[2] if len(parts) > 2 and parts[2] else "/"
        user_agent = parts[3] if len(parts) > 3 and parts[3] else ""

        full_content = f"{host}{uri} {user_agent}".lower()
        
        # Real matching: check if network rule keywords match packet content
        for rule in rules:
            matched_kw = None
            for kw in rule['keywords']:
                if kw in full_content:
                    matched_kw = kw
                    break

            if matched_kw:
                alert_count += 1
                print(f"[ALERT #{alert_count}] {rule['title']}")
                print(f"  -> Source IP: {src_ip}")
                print(f"  -> Target/URI: {host}{uri}")
                print(f"  -> Matched Keyword: '{matched_kw}'")
                print(f"  -> Tags: {rule['tags']}")
                print("-" * 50)

    print(f"\n[+] Scan complete. Analyzed {packet_count} HTTP packets. Total genuine alerts: {alert_count}")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python3 mitre_siem.py <pcap_file>")
        sys.exit(1)

    pcap_path = sys.argv[1]
    print(f"[*] Target PCAP: {pcap_path}")
    loaded_rules = load_sigma_rules(".")
    analyze_pcap(pcap_path, loaded_rules)
