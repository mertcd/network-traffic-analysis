import pyshark


def print_live_packets(interface, mac, gat):
    capture = pyshark.LiveCapture(interface, "arp")

    # Set the packet count limit, if desired
    # capture.sniff(packet_count=10)

    for packet in capture.sniff_continuously():

        if (packet.arp.src_proto_ipv4=="192.168.2.2"and packet.arp.src_hw_mac !="52:54:00:12:35:00"):
            print("Arp poison at: " + packet.arp.src_hw_mac )

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
print_live_packets(interface, "13:^11:13.!+", "192.168.3.1")
