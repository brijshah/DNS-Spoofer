from __future__ import absolute_import, division, print_function
import logging
import scapy.config
import scapy.layers.l2
import scapy.route
import socket
import math
import errno

logging.basicConfig(format='%(asctime)s %(levelname)-5s %(message)s', datefmt='%Y-%m-%d %H:%M:%S', level=logging.DEBUG)
logger = logging.getLogger(__name__)


def long2net(arg):
    if (arg <= 0 or arg >= 0xFFFFFFFF):
        raise ValueError("illegal netmask value", hex(arg))
    return 32 - int(round(math.log(0xFFFFFFFF - arg, 2)))


def toCIDRNotation(bytesNetwork, bytesNetmask):
    network = scapy.utils.ltoa(bytesNetwork)
    netmask = long2net(bytesNetmask)
    net = "%s/%s" % (network, netmask)
    if netmask < 16:
        logger.warn("%s is too big. skipping" % net)
        #print ("{} is too big. skipping".format(net))
        return None
    return net


def scanAndPrintNeighbours(net, interface, timeout=1):
    #logger.info("arping %s on %s" % (net, interface))
    print ("arping {0} on {1}".format(net, interface))
    try:
        ans, unans = scapy.layers.l2.arping(net, iface=interface, timeout=timeout, verbose=0)
        for s, r in ans.res:
            line = r.sprintf("%Ether.src%  %ARP.psrc%")
            try:
                hostname = socket.gethostbyaddr(r.psrc)
                line += " " + hostname[0]
            except socket.herror:
                # failed to resolve
                pass
            print(line)
    except socket.error as e:
        if e.errno == errno.EPERM:     # Operation not permitted
            logger.error("%s. Did you run as root?", e.strerror)
            #print ("Did you run as root?")
        else:
            raise


if __name__ == "__main__":
    for network, netmask, _, interface, address in scapy.config.conf.route.routes:
        # skip loopback network and default gw
        if network == 0 or interface == 'lo' or address == '127.0.0.1' or address == '0.0.0.0':
            continue
        if netmask <= 0 or netmask == 0xFFFFFFFF:
            continue
        net = toCIDRNotation(network, netmask)

        if interface != scapy.config.conf.iface:
            # see http://trac.secdev.org/scapy/ticket/537
            logger.warn("skipping %s because scapy currently doesn't support arping on non-primary network interfaces", net)
            #print ("skipping {} because scapy currently doesn't support arping on non-primary network interfaces".format(net))
            continue

        if net:
            scanAndPrintNeighbours(net, interface)
