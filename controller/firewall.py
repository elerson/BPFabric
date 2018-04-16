#!/usr/bin/env python
import struct
import socket

from core import eBPFCoreApplication, set_event_handler, FLOOD
from core.packets import *

def int2ip(addr):
    return socket.inet_ntoa(struct.pack("!I", addr))

def ip2long(ip):
    packedIP = socket.inet_aton(ip)
    return struct.unpack("<L", packedIP)[0]

iplist = ['10.0.1.10', '10.0.4.10']

class SimpleSwitchApplication(eBPFCoreApplication):
    @set_event_handler(Header.HELLO)
    def hello(self, connection, pkt):
        self.mac_to_port = {}

        with open('../examples/learningswitch_firewall.o', 'rb') as f:
            print("Installing the eBPF ELF")
            connection.send(InstallRequest(elf=f.read()))

	    for ip in iplist:
	    	ipsrc = struct.pack('I', ip2long(ip))
		print(ip2long(ip))
	    	connection.send(TableEntryInsertRequest(table_name="firewall", key=ipsrc, value=struct.pack('<I', 0)))

    @set_event_handler(Header.NOTIFY)
    def notify_event(self, connection, pkt):
        t, arrival, departure = struct.unpack('<III', pkt.data)
        print t, arrival, departure


if __name__ == '__main__':
    SimpleSwitchApplication().run()
