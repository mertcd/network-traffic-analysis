# network-traffic-analysis-with-bettercap

This project created to gain better insight to network flow and create some detection measures against arp poisoning attacks and detect torrent activities on live network. As part of the gainig insight to network flow I added incoming packet mapping feature to increase understanding of incoming traffic.


#Features

## Traffic mapping 

We can monitor incoming traffic from packet capture file here using necessary command. It just takes necessary ip adresses from capture file and ask an API to get latitude and longtitude of incomming connection.


###Usage


```python

tfa>> icm SYNScan_GeoIP_ChrisGreer.pcapng

filter?->> tcp.flags.syn==1 and !tcp.options
```

