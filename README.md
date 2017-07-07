# Description
This script is used to sniff DNS packets on network interfaces. The purpose is to quickly see which domain names mapped to which IP addresses. There are options to filter which domain name we want to see in the output.

# Installation
+ Mandatory:
  sudo pip install scapy

+ Optional (if we want to color-print IP addresses from Vietnam):
  sudo pip install ip_address
  sudo pip install ip_network
  sudo pip install colorama
