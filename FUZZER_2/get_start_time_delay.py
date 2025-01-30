import sys
from scapy.all import *

# обязательные переменные
pcap_file = "path_to_your_pcap_file.pcap"  # Specify your PCAP file path

# Read packets from the PCAP file
packets = rdpcap(pcap_file)

# Initialize lists to store RTTs
icmp_rtt = []
tcp_rtt = []

# Dictionaries to store request timestamps
icmp_requests = {}
tcp_requests = {}

# Process packets to calculate RTT
for packet in packets:
    if IP in packet:
        # Check if the packet is ICMP
        if ICMP in packet:
            if packet[ICMP].type == 8:  # Echo Request
                # Store the timestamp of the request
                icmp_requests[packet[ICMP].id] = packet.time
            elif packet[ICMP].type == 0:  # Echo Reply
                # Match with the corresponding request
                if packet[ICMP].id in icmp_requests:
                    start_time = icmp_requests.pop(packet[ICMP].id)  # Get the request time
                    rtt = packet.time - start_time  # Calculate RTT
                    icmp_rtt.append(rtt)

        # Check if the packet is TCP
        elif TCP in packet:
            if packet[TCP].flags & 0x02:  # SYN flag
                # Store the timestamp of the SYN request
                tcp_requests[(packet[IP].src, packet[TCP].dport)] = packet.time
            elif packet[TCP].flags & 0x12:  # SYN-ACK flag
                # Match with the corresponding SYN request
                key = (packet[IP].dst, packet[TCP].sport)
                if key in tcp_requests:
                    start_time = tcp_requests.pop(key)  # Get the request time
                    rtt = packet.time - start_time  # Calculate RTT
                    tcp_rtt.append(rtt)

# Calculate average RTT for ICMP
if icmp_rtt:
    avg_icmp_rtt = sum(icmp_rtt) / len(icmp_rtt)
    print(f"Average ICMP RTT: {avg_icmp_rtt:.6f} seconds")
else:
    print("No ICMP packets found.")

# Calculate average RTT for TCP
if tcp_rtt:
    avg_tcp_rtt = sum(tcp_rtt) / len(tcp_rtt)
    print(f"Average TCP RTT: {avg_tcp_rtt:.6f} seconds")
else:
    print("No TCP packets found.")