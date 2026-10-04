# MITRE-ATT-CK-HTTP-FILTERED-SIEM
A lightweight Python-based SIEM that parses network PCAP files, filters network-centric Sigma rules, and maps threats directly to MITRE ATT&amp;CK techniques.

## 🚀 Installation & Setup Guide

### Step 1: Install Dependencies
I Ensured `tshark` is installed on my system for packet capture dissection and field extraction:
<img width="1192" height="636" alt="needed tshark" src="https://github.com/user-attachments/assets/c918774c-1f25-4d53-b24a-e0b88f6e3ec4" />

**To evaluate traffic against real-world threat intelligence, I clone the official Sigma HQ rules repository into my working directory:**
<img width="1027" height="232" alt="1 targeted rule ingestion" src="https://github.com/user-attachments/assets/0748be64-623e-406f-a46b-c1499cca99aa" />

**I checked for Rules being live in my Dir:**
<img width="1072" height="232" alt="2 check for rule dir location live" src="https://github.com/user-attachments/assets/8a6ca68e-2ae5-4c12-ace7-451b6546ac27" />

**I created and edited the script using the terminal text editor nano.**
<img width="735" height="62" alt="3 using nano for script " src="https://github.com/user-attachments/assets/4b63898a-d302-4e31-9604-315f40aad87c" />

**The actual SIEM script :1/5**
<img width="1102" height="530" alt="n1" src="https://github.com/user-attachments/assets/ee93f0ad-d3d6-4333-b03c-e542eb215e0b" />

This function, extract_keywords_from_detection, is a helper utility designed to parse and extract searchable lowercase string patterns out of a Sigma rule's YAML detection block.
It handles different data structures within the rule logic by checking whether values are strings, lists, or nested dictionaries recursively, ensuring all matching strings are collected to scan network traffic or logs effectively.

**The actual SIEM script :2/5**
<img width="1565" height="885" alt="image" src="https://github.com/user-attachments/assets/f47ae5ba-dbf9-4c83-ae2b-dc296e967b9a" />

**Step-by-Step Breakdown:**
Recursive Directory Traversal (os.walk):
Scans through the specified rules directory to locate all .yml and .yaml threat intelligence files.

YAML Safety Parsing (yaml.safe_load):
Safely opens and parses each file, extracting metadata like the rule title, log source, tags, and detection logic.

Log Source Filtering (valid_log_sources):
Restricts ingestion strictly to network and web traffic sources (webserver, proxy, zeek, firewall, dns, packet, http), ignoring unrelated endpoint/Windows event logs.

Keyword Extraction & Quality Filtering (len(kw) > 3):
Calls the recursive helper function to pull searchable strings, then automatically drops short keywords under 4 characters. This prevents common URL chunks (like GET or cmd) from flooding your scan engine with false positives.

MITRE ATT&CK Tag Validation:
Confirms that the rule contains official MITRE ATT&CK framework tags (attack.) and retains valid search keywords.

Rule Compilation:
Packages the validated rule's title, tags, and keywords into a structured dictionary and appends it to your active rule set.
Let me know if you need this formatted into a specific code comment block or if you are ready to wrap up your final GitHub commit!

**The actual SIEM script:3/3**
<img width="1067" height="895" alt="image" src="https://github.com/user-attachments/assets/9002a47d-cb06-448a-8baa-21e6c177ec44" />
<img width="1436" height="882" alt="image" src="https://github.com/user-attachments/assets/7939f68c-dbec-43c0-b48f-c7b5b8e85b9f" />
<img width="726" height="232" alt="image" src="https://github.com/user-attachments/assets/5710c38f-b554-4548-9627-f218aa16ca87" />

**Main Execution & PCAP Analysis Engine (analyze_pcap & Entrypoint)**

This final block contains the core orchestration logic that runs the packet capture analysis, matches traffic against your intelligence rules, and handles command-line execution:
PCAP Validation: Checks if the target PCAP file exists on disk before running commands, gracefully exiting with an error message if it's missing.
Tshark Integration (subprocess): Automates Wireshark's command-line tool (tshark) to parse HTTP traffic, isolating essential fields (ip.src, http.host, http.request.uri, and http.user_agent) into tab-separated output.
Stream Processing & Normalization: Iterates through the extracted packet lines, constructs a unified lowercased string (full_content) from the host, URI, and user agent, and keeps a running count of total packets analyzed.
Threat Matching & Alerting: Compares every loaded Sigma rule's keywords against the packet content. When a match occurs, it increments the alert count and prints a detailed forensic breakdown (Source IP, target URI, matched keyword, and MITRE ATT&CK tags).
Command-Line Interface (CLI): Uses Python's sys.argv to accept the target PCAP file as a command-line argument (e.g., python3 mitre_siem.py capture.pcap), automatically triggering the rule loading and scanning functions.

## Acknowledgements & Development Workflow
This project was built as a hands-on cybersecurity portfolio piece focusing on Python scripting, network traffic analysis, and threat intelligence mapping. AI-driven development workflows and assistant tools were leveraged to help structure the codebase, refine data-parsing logic (such as recursive Sigma rule ingestion and keyword filtering), and draft comprehensive technical documentation.










