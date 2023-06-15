import pyshark

def print_live_packets(interface):
    capture = pyshark.LiveCapture(interface)

    # Set the packet count limit, if desired
    # capture.sniff(packet_count=10)

    for packet in capture.sniff_continuously():
        # Print the packet details

        try :
            packet_info = {
            'Source IP': packet.ip.src,
            'Destination IP': packet.ip.dst,
            'Protocol': packet.highest_layer,
            'Packet Size': packet.length,
            'Timestamp': packet.sniff_timestamp,
            # Add more fields as per your requirement
        }
        except:
            print("err")
            packet_info="err"

        print(packet_info)

# Specify the interface to capture packets from
interface = 'wi-fi'

# Start printing live packets
print_live_packets(interface)