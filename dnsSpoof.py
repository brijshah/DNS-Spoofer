#!/usr/bin/python

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

#import arpSpoof file?
# from arpSpoof import *

# Get mac address of router and victim

# Enable ip forwarding (should be based on os, linux or OSX)
	# darwin(osx)
	# forward: sysctl -w net.inet.ip.forwarding=1
	# not forward: sysctl -w net.inet.ip.forwarding=0

	# linux
	# forward: echo 1 > /proc/sys/net/ipv4/ip_forward
	# note forward: echo 0 > /proc/sys/net/ipv4/ip_forward

# initiate arp spoofing (make sure to kill process cleanly on exit)

# sniff for DNS
# filter='udp and port 53 and src'

	# make sure we can sniff packets
	# if packet has UDP layer
	# look for DNS query
	# obtain domain name 