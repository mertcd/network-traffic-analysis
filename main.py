import folium as folium
import pandas as pd
import requests
from scapy.all import *
from scapy.layers.inet import TCP

import pyshark


# Read the PCAP file
def capturePackets(name, filter):
    return pyshark.FileCapture(name, display_filter=filter)


# Filter the packets by protocol


# Extract the data from the packets
# data = [packet for packet in filtered_capture]


# Extract the source IP addresses
def extractsrc(capture):
    src_ips = [packet.ip.src for packet in capture]
    if len(src_ips) > 100:
        src_ips = src_ips[:100]
    return src_ips


# dst_ports = [packet.tcp.dstport for packet in capture]

# Print the information
"""for src, dst in zip(src_ips, dst_ports):
    print(f'Source IP: {src} Destination Port: {dst}')"""


def convert_ip_to_location(ip_address=[], params=[]):
    # valid parameters to pass to the API
    valid_params = ['status', 'message', 'continenet', 'continentCode', 'country',
                    'countryCode', 'region', 'regionName', 'city', 'district',
                    'zip', 'lat', 'lon', 'timezone', 'offset', 'currency', 'isp',
                    'org', 'as', 'asname', 'reverse', 'mobile', 'proxy', 'hosting',
                    'query']

    # input checks
    assert isinstance(ip_address, list), 'The ip_address must be passed in a list'
    assert ip_address, 'You must pass at least one ip address to the function'
    assert isinstance(params, list), 'You must pass at least one parameter'
    for param in params:
        assert param in valid_params, f"{param} is not a valid parameter. List of valid params: {valid_params}"

    # the base URL for the API to connect to (JSON response)
    url = 'http://ip-api.com/json/'

    # specify query parameters we want to include in the response
    # and convert to properly formatted search string
    params = ['status', 'country', 'city', 'lat', 'lon', 'mobile']
    params_string = ','.join(params)

    # create a dataframe to store the responses
    df = pd.DataFrame(columns=['ip_address'] + params)

    # make the response for each of the IP addresses
    for ip in ip_address:
        resp = requests.get(url + ip, params={'fields': params_string})
        try:
            info = resp.json()

            if info["status"] == 'success':
                # if response is okay, append to dataframe
                info = resp.json()
                info.update({'ip_address': ip})
                df = df._append(info, ignore_index=True)
            else:
                # if there was a problem with the response, trigger a warning
                logging.warning(f'Unsuccessful response for IP: {ip}')
        except:
            logging.warning(f'Unsuccessful response for IP: {ip}')
    # return the dataframe with all the information
    return df


def capturePacketProtocol(interface, protocol):
    capture = pyshark.LiveCapture(interface)

    for packet in capture.sniff_continuously():

        try:
            packet_info = [
                packet.ip.dst,
                packet.highest_layer
            ]
        except:

            packet_info = "err"
        if packet_info[1]==protocol:
            print("Torrent activity on "+packet_info[0])


def mappit(src_ips):
    data = convert_ip_to_location(src_ips, ["lat", "lon", "city"])
    m = folium.Map(location=[20, 0], tiles="OpenStreetMap", zoom_start=2)

    # add marker one by one on the map
    for i in range(0, len(data)):
        folium.Marker(
            location=[data.iloc[i]['lat'], data.iloc[i]['lon']],
            popup=data.iloc[i]['city'],
        ).add_to(m)

    # Show the map again
    m.show_in_browser()
def arp_live_packets(interface, gat, mac):
    capture = pyshark.LiveCapture(interface, "arp")

    for packet in capture.sniff_continuously():

        if (packet.arp.src_proto_ipv4==gat and packet.arp.src_hw_mac !=mac):
            print("Arp poison at: " + packet.arp.src_hw_mac )



if __name__ == '__main__':
    que = input("tfa>>")
    arg = que.split(" ")
    print(arg[0])
    if str(arg[0]) == 'icm':#icm SYNScan_GeoIP_ChrisGreer.pcapng
        fil = input("filter?->>")
        #tcp.flags.syn==1 and !tcp.options
        packets = capturePackets(arg[1], fil)
        srcip = extractsrc(packets)
        mappit(srcip)
    elif arg[0] == "mitm":#mitm mitm.pcapng 192.168.2.2 52:54:00:12:35:00
        name = arg[1]
        gat = arg[2]
        mac = arg[3]
        filter = "((arp.src.proto_ipv4 == " + gat + ") && (arp.opcode == 2)) && !(arp.src.hw_mac == " + mac + ")"
        packets = capturePackets(arg[1], filter)

        a = [p.eth.src for p in packets]
        if len(a) > 0:
            print("Arp poison macs are" + str(set(a)))
    elif arg[0] == "btlstn" or arg[0] == "Btlstn":#btlstn wi-fi
        capturePacketProtocol(arg[1],'BT-DHT')
    elif arg[0]=="arpls":
        arp_live_packets(arg[1],arg[2],arg[3])
    else:
        print("Comman 1: Show pcap file incoming packet")
# 192.168.2.2 52:54:00:12:35:00
