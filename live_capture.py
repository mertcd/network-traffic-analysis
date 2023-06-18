import pyshark

def print_live_packets(interface,mac ,gat):
    capture = pyshark.LiveCapture(interface,"arp")

    # Set the packet count limit, if desired
    # capture.sniff(packet_count=10)

    for packet in capture.sniff_continuously():
        # Print the packet details
        if ((packet.src.proto_ipv4 == " + gat + ") and (packet.opcode == 2)) and not (packet.src.hw_mac == " + mac + "):
            print("Arp poisoning at "+packet.src.proto_ipv4)

        """ try :
            packet_info = {
            'Source IP': packet.ip.src,
            'Destination IP': packet.ip.dst,
            'Protocol': packet.highest_layer,

            # Add more fields as per your requirement
        }
        except:
            print("err")
            packet_info="err"

        print(packet_info)
"""
# Specify the interface to capture packets from
interface = 'wi-fi'

# Start printing live packets
print_live_packets(interface)