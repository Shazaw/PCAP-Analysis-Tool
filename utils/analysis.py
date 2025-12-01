import pyshark
import os
import collections

def analyze_pcap(filepath):
    """
    Analyzes a PCAP file for basic statistics and potential malicious activity.
    """
    if not os.path.exists(filepath):
        return {"error": "File not found"}

    summary = {
        "packet_count": 0,
        "protocols": collections.Counter(),
        "src_ips": collections.Counter(),
        "dst_ips": collections.Counter(),
        "malicious_activity": []
    }

    # Suspicious ports often used for attacks or malware
    SUSPICIOUS_PORTS = {23, 4444, 6667, 31337}
    
    # Suspicious User-Agents often used by malware
    SUSPICIOUS_USER_AGENTS = [
        'python-requests', 'libwww-perl', 'curl', 'wget', 
        'winhttp', 'go-http-client', 'okhttp', 'httpclient'
    ]
    
    # Tracking for various detection heuristics
    smtp_sessions = collections.defaultdict(lambda: {'packets': 0, 'data_size': 0})
    http_sessions = collections.defaultdict(list)
    dns_queries = collections.defaultdict(int) 
    
    # Tracking for port scanning detection (src_ip -> set of dst_ports)
    port_scan_tracker = collections.defaultdict(set)

    try:
        # keep_packets=False to save memory on large files
        capture = pyshark.FileCapture(filepath, keep_packets=False)

        for packet in capture:
            summary["packet_count"] += 1
            
            # Protocol counting
            summary["protocols"][packet.highest_layer] += 1

            # IP Layer analysis
            if 'IP' in packet:
                src_ip = packet.ip.src
                dst_ip = packet.ip.dst
                summary["src_ips"][src_ip] += 1
                summary["dst_ips"][dst_ip] += 1

                # Check for suspicious ports (TCP/UDP)
                dst_port = None
                if 'TCP' in packet:
                    dst_port = int(packet.tcp.dstport)
                elif 'UDP' in packet:
                    dst_port = int(packet.udp.dstport)
                
                if dst_port:
                    port_scan_tracker[src_ip].add(dst_port)
                    
                    if dst_port in SUSPICIOUS_PORTS:
                        # Extract full details
                        payload_preview = "N/A"
                        full_hex = "N/A"
                        full_ascii = "N/A"
                        
                        # Enhanced packet details
                        packet_details = {
                            "frame_num": packet.number if hasattr(packet, 'number') else "N/A",
                            "frame_len": packet.length if hasattr(packet, 'length') else "N/A",
                            "ip_ttl": packet.ip.ttl if hasattr(packet.ip, 'ttl') else "N/A",
                            "ip_id": packet.ip.id if hasattr(packet.ip, 'id') else "N/A",
                            "tcp_seq": packet.tcp.seq if 'TCP' in packet and hasattr(packet.tcp, 'seq') else "N/A",
                            "tcp_ack": packet.tcp.ack if 'TCP' in packet and hasattr(packet.tcp, 'ack') else "N/A",
                            "tcp_flags": packet.tcp.flags if 'TCP' in packet and hasattr(packet.tcp, 'flags') else "N/A",
                            "tcp_window": packet.tcp.window_size if 'TCP' in packet and hasattr(packet.tcp, 'window_size') else "N/A"
                        }
                        
                        try:
                            if hasattr(packet, 'data'):
                                payload_preview = str(packet.data.data)[:50] + "..."
                                full_hex = packet.data.data
                                # Try to convert hex to ascii
                                try:
                                    full_ascii = bytes.fromhex(full_hex.replace(':', '')).decode('utf-8', errors='replace')
                                except:
                                    full_ascii = "Could not decode to ASCII"
                        except:
                            pass

                        # SIEM Intelligence: Risk scoring and categorization
                        severity = "HIGH"
                        risk_score = 75
                        mitre_tactic = "TA0011"  # Command and Control
                        mitre_technique = "T1571"  # Non-Standard Port
                        threat_category = "Malware Communication"
                        
                        if dst_port == 23:  # Telnet
                            severity = "CRITICAL"
                            risk_score = 90
                            mitre_tactic = "TA0001"  # Initial Access
                            mitre_technique = "T1078"  # Valid Accounts
                            threat_category = "Credential Access"
                        elif dst_port in [4444, 31337]:  # Backdoor ports
                            severity = "CRITICAL"
                            risk_score = 95
                            mitre_tactic = "TA0011"  # Command and Control
                            mitre_technique = "T1219"  # Remote Access Software
                            threat_category = "Malware/Backdoor"
                        elif dst_port == 6667:  # IRC
                            severity = "HIGH"
                            risk_score = 80
                            mitre_tactic = "TA0011"  # Command and Control
                            mitre_technique = "T1071.001"  # Application Layer Protocol
                            threat_category = "Botnet C2"

                        summary["malicious_activity"].append({
                            "type": "Suspicious Port",
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "port": dst_port,
                            "protocol": packet.highest_layer,
                            "timestamp": str(packet.sniff_time),
                            "payload": payload_preview,
                            "full_hex": full_hex,
                            "full_ascii": full_ascii,
                            "details": f"Traffic on suspicious port {dst_port}",
                            "severity": severity,
                            "risk_score": risk_score,
                            "mitre_tactic": mitre_tactic,
                            "mitre_technique": mitre_technique,
                            "threat_category": threat_category,
                            "packet_details": packet_details
                        })
                
                # Check for SMTP exfiltration (AgentTesla commonly uses this) - INCLUDING ENCRYPTED
                # Detect on ports 25 (SMTP), 587 (submission), 465 (SMTPS)
                if dst_port in [25, 587, 465]:
                    smtp_sessions[src_ip]['packets'] += 1
                    # Try to get payload size even if encrypted
                    try:
                        if hasattr(packet, 'tcp'):
                            if hasattr(packet.tcp, 'len'):
                                smtp_sessions[src_ip]['data_size'] += int(packet.tcp.len)
                            elif hasattr(packet.tcp, 'payload'):
                                smtp_sessions[src_ip]['data_size'] += len(str(packet.tcp.payload))
                    except:
                        pass
                
                # Detect TLS/SSL on SMTP ports (AgentTesla often uses encrypted exfiltration)
                if dst_port in [465, 587]:
                    # Flag ANY connection to secure SMTP ports
                    summary["malicious_activity"].append({
                        "type": "Encrypted SMTP Connection",
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "port": dst_port,
                        "protocol": "SMTPS/TLS",
                        "timestamp": str(packet.sniff_time),
                        "payload": "Encrypted",
                        "full_hex": "N/A",
                        "full_ascii": f"Connection to SMTP port {dst_port}",
                        "details": f"Connection to encrypted SMTP port {dst_port} (common AgentTesla/malware exfiltration)",
                        "severity": "HIGH",
                        "risk_score": 85,
                        "mitre_tactic": "TA0010",
                        "mitre_technique": "T1048",
                        "threat_category": "Data Exfiltration",
                        "packet_details": {}
                    })
                
                # FLAG ANY TLS TRAFFIC (very aggressive - catches encrypted malware)
                if packet.highest_layer == 'TLS' or packet.highest_layer == 'SSL':
                    summary["malicious_activity"].append({
                        "type": "Encrypted Traffic",
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "port": dst_port if dst_port else "Unknown",
                        "protocol": "TLS/SSL",
                        "timestamp": str(packet.sniff_time),
                        "payload": "Encrypted",
                        "full_hex": "N/A",
                        "full_ascii": "TLS/SSL encrypted communication",
                        "details": f"Encrypted TLS/SSL traffic detected on port {dst_port} (potential data exfiltration)",
                        "severity": "MEDIUM",
                        "risk_score": 50,
                        "mitre_tactic": "TA0011",
                        "mitre_technique": "T1573",
                        "threat_category": "Encrypted C2",
                        "packet_details": {}
                    })
                
                # Check for suspicious HTTP traffic
                if dst_port == 80 or dst_port == 8080:
                    if hasattr(packet, 'http'):
                        # Check for suspicious User-Agent
                        if hasattr(packet.http, 'user_agent'):
                            user_agent = str(packet.http.user_agent).lower()
                            for suspicious_ua in SUSPICIOUS_USER_AGENTS:
                                if suspicious_ua.lower() in user_agent:
                                    payload_preview = "N/A"
                                    full_hex = "N/A"
                                    full_ascii = f"User-Agent: {packet.http.user_agent}"
                                    
                                    try:
                                        if hasattr(packet, 'data'):
                                            full_hex = packet.data.data
                                            full_ascii = bytes.fromhex(full_hex.replace(':', '')).decode('utf-8', errors='replace')
                                    except:
                                        pass
                                    
                                    summary["malicious_activity"].append({
                                        "type": "Suspicious User-Agent",
                                        "src_ip": src_ip,
                                        "dst_ip": dst_ip,
                                        "port": dst_port,
                                        "protocol": "HTTP",
                                        "timestamp": str(packet.sniff_time),
                                        "payload": user_agent[:50],
                                        "full_hex": full_hex,
                                        "full_ascii": full_ascii,
                                        "details": f"Malware-like User-Agent: {user_agent}"
                                    })
                        
                        # Check for base64 encoded data (common exfiltration technique)
                        if hasattr(packet.http, 'file_data'):
                            file_data = str(packet.http.file_data)
                            if len(file_data) > 100 and any(c in file_data for c in ['==', '+/', 'base64']):
                                summary["malicious_activity"].append({
                                    "type": "Suspicious HTTP Data",
                                    "src_ip": src_ip,
                                    "dst_ip": dst_ip,
                                    "port": dst_port,
                                    "protocol": "HTTP",
                                    "timestamp": str(packet.sniff_time),
                                    "payload": file_data[:50] + "...",
                                    "full_hex": "N/A",
                                    "full_ascii": file_data[:500],
                                    "details": "Possible base64 encoded data exfiltration"
                                })
                
                # Check for DNS tunneling
                if dst_port == 53:
                    if hasattr(packet, 'dns') and hasattr(packet.dns, 'qry_name'):
                        domain = str(packet.dns.qry_name)
                        dns_queries[domain] += 1
                        # Long subdomain names are suspicious
                        if '.' in domain and len(domain.split('.')[0]) > 30:
                            summary["malicious_activity"].append({
                                "type": "Suspicious DNS Query",
                                "src_ip": src_ip,
                                "dst_ip": dst_ip,
                                "port": 53,
                                "protocol": "DNS",
                                "timestamp": str(packet.sniff_time),
                                "payload": domain,
                                "full_hex": "N/A",
                                "full_ascii": f"DNS Query: {domain}",
                                "details": f"Unusually long subdomain (potential DNS tunneling): {domain}"
                            })

        capture.close()

        # Detect Port Scanning (heuristic: > 20 unique ports touched by one IP)
        for src_ip, ports in port_scan_tracker.items():
            if len(ports) > 20:
                 summary["malicious_activity"].append({
                    "type": "Potential Port Scan",
                    "src_ip": src_ip,
                    "dst_ip": "Multiple",
                    "port": "Multiple",
                    "protocol": "TCP/UDP",
                    "timestamp": "N/A",
                    "payload": "N/A",
                    "full_hex": "N/A",
                    "full_ascii": "N/A",
                    "details": f"Scanned {len(ports)} unique ports: {list(ports)}",
                    "severity": "HIGH",
                    "risk_score": 80,
                    "mitre_tactic": "TA0043",
                    "mitre_technique": "T1046",
                    "threat_category": "Reconnaissance",
                    "packet_details": {}
                })
        
        # Detect SMTP exfiltration (common in AgentTesla) - EXTREMELY SENSITIVE
        for src_ip, smtp_data in smtp_sessions.items():
            # ANY SMTP activity is flagged (very aggressive detection)
            if smtp_data['packets'] > 0:
                summary["malicious_activity"].append({
                    "type": "SMTP Activity",
                    "src_ip": src_ip,
                    "dst_ip": "SMTP Server",
                    "port": "25/587/465",
                    "protocol": "SMTP",
                    "timestamp": "N/A",
                    "payload": "N/A",
                    "full_hex": "N/A",
                    "full_ascii": f"Packets: {smtp_data['packets']}, Data: {smtp_data['data_size']} bytes",
                    "details": f"SMTP activity detected: {smtp_data['packets']} packets, {smtp_data['data_size']} bytes (AgentTesla commonly exfiltrates via SMTP)",
                    "severity": "MEDIUM",
                    "risk_score": 60,
                    "mitre_tactic": "TA0010",
                    "mitre_technique": "T1048.003",
                    "threat_category": "Email Exfiltration",
                    "packet_details": {}
                })

        # Convert counters to dicts for JSON serialization
        summary["protocols"] = dict(summary["protocols"].most_common(10))
        summary["src_ips"] = dict(summary["src_ips"].most_common(10))
        summary["dst_ips"] = dict(summary["dst_ips"].most_common(10))

        return summary

    except Exception as e:
        return {"error": str(e)}
