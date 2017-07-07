# Description
This script is used to sniff DNS packets on network interfaces. The purpose is to quickly see which domain names mapped to which IP addresses. There are options to filter which domain name we want to see in the output.

# Installation
Install the scapy module: 
```
pip install scapy
```

If we want to color-print IP addresses from Vietnam, we need to install some additional modules:
```
pip install ip_address
pip install ip_network
pip install colorama
```

# Usage
Assign execute permission for the script:
```
# chmod a+x dns_sniff.py
```

Show the available options:
```
# ./dns_sniff.py --help
usage: dns_sniff.py [-h] [-n name [name ...]] [-s src [src ...]] [-i iface]
                    [-c count] [-g]

DNS sniffing to quickly find name to IP mapping

optional arguments:
  -h, --help          show this help message and exit
  -n name [name ...]  domain name to find name <-> IP (default all)
  -s src [src ...]    host from which to sniff DNS packets (default all)
  -i iface            interface on which to sniff DNS packets (default all)
  -c count            number of DNS packets to sniff (default infinity)
  -g                  color-print Vietnam' IPs (default not set)
```

Sample output:
```
# ./dns_sniff.py -n google -i bond1
Sniffing DNS packets...
10.client-channel.google.com. <-> 74.125.68.189 (TTL=300, queried by 192.0.2.15)
10.client-channel.google.com. <-> 74.125.68.189 (TTL=300, queried by 192.0.2.16)
r2---sn-q4fl6nle.googlevideo.com. <-> 74.125.1.152 (TTL=1800, queried by 192.0.2.15)
10.client-channel.google.com. <-> 2404:6800:4003:c02::bd (TTL=300, queried by 192.0.2.15)
ytstatic.l.google.com. <-> 74.125.68.102 (TTL=300, queried by 192.0.2.16)
sb.l.google.com. <-> 2404:6800:4003:80c::200e (TTL=300, queried by 192.0.2.16)
r7---sn-i3b7kned.googlevideo.com. <-> 74.125.164.204 (TTL=1800, queried by 192.0.2.15)
```
