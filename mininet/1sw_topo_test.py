#!/usr/bin/env python

from mininet.net import Mininet
from mininet.topo import Topo
from mininet.cli import CLI
from mininet.node import Controller
import os

from eBPFSwitch import eBPFSwitch, eBPFHost
from functools import partial

from time import sleep


import socket
 
UDP_IP = "127.0.0.1"
UDP_PORT = 5007
MESSAGE = "EXP"
 

class SingleSwitchTopo(Topo):
    def __init__(self, **opts):
        # Initialize topology and default options
        Topo.__init__(self, **opts)

        switch = self.addSwitch('s1',
            switch_path="../softswitch/softswitch")

        for h in xrange(1): #TODO number of hosts
            host = self.addHost('h%d' % (h + 1),
                                ip = "10.0.%d.10/24" % h,
                                mac = '00:04:00:00:00:%02x' %h)

            self.addLink(host, switch)



		


def main():

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    

    topo = SingleSwitchTopo()
    net = Mininet(topo = topo, host = eBPFHost, switch = eBPFSwitch, controller = None)

    net.start()

    h1 = net.get('h1')  
    result = h1.cmd('./pcap.sh')
    print 'teste'
    sock.sendto(MESSAGE, (UDP_IP, UDP_PORT))
    exit()
    #result = h1.cmd('pcap.sh')
    CLI(net)
    net.stop()
    print('teste')

if __name__ == '__main__':
    main()
