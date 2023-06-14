import pyshark

def extract_packet_details(capture_file):
    capture = pyshark.FileCapture(capture_file)
    packet_list = []

    for packet in capture:
        packet_info = {
            'Source IP': packet.ip.src,
            'Destination IP': packet.ip.dst,
            'Protocol': packet.highest_layer,
            'Packet Size': packet.length,
            'Timestamp': packet.sniff_timestamp,
            # Add more fields as per your requirement
        }
        packet_list.append(packet_info)

    capture.close()
    return packet_list

# Specify the path to your capture file
capture_file_path = 'ff.pcapng'

# Extract the packet details
packet_list = extract_packet_details(capture_file_path)

# Print the list of packet details
for packet in packet_list:
    print(packet)
