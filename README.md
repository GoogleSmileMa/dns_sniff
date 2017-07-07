# Description
This script is used to sniff DNS packets on network interfaces. The purpose is to quickly see which domain names mapped to which IP addresses. There are options to filter which domain name we want to see in the output.

# Installation
`pip install scapy`

If we want to color-print IP addresses from Vietnam, we need to install some additional packages:
```pip install ip_address
sudo pip install ip_network
sudo pip install colorama```
