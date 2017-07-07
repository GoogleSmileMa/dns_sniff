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
```
# chmod a+x dns_sniff.py
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
