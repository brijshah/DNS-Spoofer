#!/usr/bin/python

#-----------------------------------------------------------------------------
#-- SOURCE FILE:    detect.py -   DNS Spoof Detection
#--
#-- FUNCTIONS:      storeDetect()
#--                 parse()
#--					main()
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

import argparse, time, logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

dictionary = {}
timeDictionary = {}
deleteFromTime = set()
interval = 5

#-----------------------------------------------------------------------------
#-- FUNCTION:       storeDetect(packet)
#--
#-- VARIABLES(S):   packet - the packet to analyze
#--
#-- NOTES:
#-- 
#-----------------------------------------------------------------------------
def storeDetect(packet):
	if DNS in packet:
		dnsLayer = packet.getlayer('DNS')
		ip = packet.getlayer('IP')

		if (layer.qr = 0):
			t = ('REQ', ip.src, ip.dst, dnsLayer.qd.name)
			dictionary[layer.id] = set([])
			dictionary[layer.id].add(t)

			currentTime = int(time.time())
			if timeDictionary.has_key(currentTime):
				timeDictionary[currentTime].add(dnsLayer.id)
			else:
				timeDictionary[currentTime] = set()
				timeDictionary[currentTime].add(dnsLayer.id)
		else:
			count = dnsLayer.ancount

			if count == 0:
				ans = 'null'
			if count == 1:
				ans = dnsLayer.an.rdata
			else:
				ans = ""
				x = dnsLayer.an
				for i in range(0, dnsLayer.ancount):
					if x.type == 1:
						ans = x.rdata + ',' + ans
					x = x.payload
				ans = ans[:len(ans) - 1]

			dictionary[dnsLayer.id].add(('AN', ip.src, ip.dst, dnsLayer.qd.qname, ans))

		if len(dictionary[dnsLayer.id] > 2):
			answer = ""
			for s in dictionary[dnsLayer.id]:
				i = 1
				if s[0] == 'AN':
					answer = ' AN' + str(i)+" :" +s[4]
					i += 1
			answer = answer[1:]
			print 'DETECT: REQ: %s NAM: %s SRC: %s:%s DST: %s:%s %s' % (str(dnsLayer.id) , dnsLayer.qd.qname, ip.dst, str(ip[UDP].dport), ip.src, str(ip[UDP].sport), answer)

#-----------------------------------------------------------------------------
#-- FUNCTION:       parse(packet)
#--
#-- VARIABLES(S):   packet - the packet to analyze
#--
#-- NOTES:
#-- 
#-----------------------------------------------------------------------------
def parse(packet):
	if DNS in packet:
		minimumAllowedTime = time.time() - interval

		deleteFromTime = set()
		for i in timeDictionary:
			if i < minimumAllowedTime:
				deleteFromTime.add(i)
				for id in timeDictionary[i]:
					deleteFromTime.add(id)

		for id in deleteFromTime:
			if(dictionary.has_key(id)):
				del(dictionary[id])

		for i in deleteFromTime:
			if i < minimumAllowedTime:
				if timeDictionary.has_key(i):
					del timeDictionary[i]

	storeDetect(packet)

#-----------------------------------------------------------------------------
#-- FUNCTION:       main()
#--
#-- NOTES:
#-- 
#-----------------------------------------------------------------------------
def main():
	interface = ()
	cmdParser = argparse.ArgumentParser(description="DNS Detect")
	cmdParser.add_argument('-i',
						'--interface',
						dest='iface',
						help='Network Interface',
						required=True)
	cmdParser.add_argument('-t',
						'--time',
						dest='time',
						help='time interval',
						required=True)
	args = cmdParser.parse_args()

	if args.iface:
		interface = args.iface
	if args.time:
		interval = args.time
	else:
		interval = 5

	if interface:
		sniff(iface =interface, prn=parse, filter='port 53')

if __name__ == '__main__':
	try:
		main()
	except KeyboardInterrupt:
		print 'exiting..'

