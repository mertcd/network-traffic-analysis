# network-traffic-analysis-with-bettercap

This project created to gain better insight to network flow and create some detection measures against arp poisoning attacks and detect torrent activities on live network. As part of the gainig insight to network flow I added incoming packet mapping feature to increase understanding of incoming traffic.


#Features

## Traffic mapping 

We can monitor incoming traffic from packet capture file here using necessary command. It just takes necessary ip adresses from capture file and ask an API to get latitude and longtitude of incoming connection.


icm [pcapng filemane]


pyshark filter

```python

tfa>> icm SYNScan_GeoIP_ChrisGreer.pcapng

filter?->> tcp.flags.syn==1 and !tcp.options
```
![alt text](https://github.com/mertcd/network-traffic-analysis/blob/d1df1b3e3ceb0c475df0d56b43f7d09299fca44b/Ekran%20g%C3%B6r%C3%BCnt%C3%BCs%C3%BC%202023-06-20%20210041.png)



## Arp Poisoning Live Detection 

We can set a sniffer for arp packets detect if there is someone trying to introduce new mac adress in our network enviroment.We u.se arpls keyword and interface name it could be wi-fi or eth0
then we can enter the correct gateway ip and gateway mac.

arpls [interface name] [gateway ip ] [gateway mac]

```python

tfa>> arpls wi-fi 192.168.2.2 11:12:33:44:55

```

```python
arp poisoning mac adress: 33:22:33:44:55:55

```
