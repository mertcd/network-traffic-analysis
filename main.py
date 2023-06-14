from scapy.all import *
from scapy.layers.inet import TCP

import pyshark

# Read the PCAP file
capture = pyshark.FileCapture('ss.pcapng',display_filter='tcp')


# Filter the packets by protocol
filtered_capture = capture

# Extract the data from the packets
data = [packet["ip"] for packet in filtered_capture]

# Print the data
for d in data:
    print(d)

# Extract the source IP addresses
src_ips = [packet.ip.src for packet in capture]

# Extract the destination ports
dst_ports = [packet.ip.dst for packet in capture]

# Print the information
for src, dst in zip(src_ips, dst_ports):
    print(f'Source IP: {src} Destination Port: {dst}')