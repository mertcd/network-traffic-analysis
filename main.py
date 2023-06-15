import folium as folium
import pandas as pd
import requests
from scapy.all import *
from scapy.layers.inet import TCP

import pyshark

# Read the PCAP file
def capturePackets(name,filter):
    capture = pyshark.FileCapture('SYNScan_GeoIP_ChrisGreer.pcapng',display_filter='tcp')


# Filter the packets by protocol
filtered_capture = capture

# Extract the data from the packets
#data = [packet for packet in filtered_capture]



# Extract the source IP addresses
src_ips = [packet.ip.src for packet in capture]
src_ips = src_ips[:100]
# Extract the destination ports
#dst_ports = [packet.tcp.dstport for packet in capture]

# Print the information
"""for src, dst in zip(src_ips, dst_ports):
    print(f'Source IP: {src} Destination Port: {dst}')"""

def convert_ip_to_location(ip_address=[], params=[]):
    '''
    This function takes a list of IP addresses, sends them to
    an API service and records the response which is associated
    with the location of the given IP address. A pd.DataFrame
    will be returned with all of the IP addresses and their
    location parameters.
    Parameters
    ----------
    ip_address: list[str]
        a list of the ip addresses that we want to send to the API
    params: list[str]
        a list of the parameters we would like to receive back from
        the API when we make our request
    Returns
    -------
    pd.DataFrame
        a pandas DataFrame that contains the original IP addresses as
        well as all of the location information retrieved for each from
        the API.
    '''

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
def mappit(df):

    data = convert_ip_to_location(src_ips,["lat","lon","city"])
    m = folium.Map(location=[20,0], tiles="OpenStreetMap", zoom_start=2)

# add marker one by one on the map
    for i in range(0,len(data)):
        folium.Marker(
        location=[data.iloc[i]['lat'], data.iloc[i]['lon']],
        popup=data.iloc[i]['city'],
        ).add_to(m)

# Show the map again
    m.show_in_browser()


if __name__ == '__main__':
    que = input("tfa>>")
    arg = que.split(" ")
    if que[0] =="ıcm":

