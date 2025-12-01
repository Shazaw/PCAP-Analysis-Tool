from scapy.all import *
import random

def generate_pcap(filename):
    packets = []
    
    attacker_ip = "192.168.1.66"
    victim_ip = "192.168.1.200"
    scanner_ip = "10.0.0.13"
    normal_ip = "192.168.1.5"

    print(f"Generating malicious traffic for {filename}...")

    # 1. Suspicious Ports (Telnet & Metasploit default)
    print("- Adding suspicious port traffic (23, 4444)...")
    packets.append(IP(src=attacker_ip, dst=victim_ip)/TCP(dport=23, flags="S"))
    packets.append(IP(src=attacker_ip, dst=victim_ip)/TCP(dport=4444, flags="S"))
    packets.append(IP(src=attacker_ip, dst=victim_ip)/TCP(dport=31337, flags="S"))

    # 2. Port Scanning (Scanner IP -> Victim IP on >20 ports)
    print("- Adding port scan traffic...")
    for i in range(30):
        dport = random.randint(1024, 65535)
        packets.append(IP(src=scanner_ip, dst=victim_ip)/TCP(dport=dport, flags="S"))

    # 3. Normal Traffic (HTTP/HTTPS)
    print("- Adding normal traffic...")
    for i in range(20):
        packets.append(IP(src=normal_ip, dst=victim_ip)/TCP(dport=80, flags="PA")/"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        packets.append(IP(src=victim_ip, dst=normal_ip)/TCP(sport=80, flags="PA")/"HTTP/1.1 200 OK\r\n\r\n")

    wrpcap(filename, packets)
    print(f"Done! Saved to {filename}")

if __name__ == "__main__":
    generate_pcap("malicious_test.pcap")
