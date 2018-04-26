#!/usr/bin/env python
import struct
import socket
import time, threading

from core import eBPFCoreApplication, set_event_handler, FLOOD
from core.packets import *
import time


def tabulate(rows, headers=None):
    if not rows or len(rows) == 0:
        print('<Empty Table>')
        return

    # Find the largest possible value for each column
    columns_width = [ max([ len(str(row[i])) for row in rows ]) for i in range(len(rows[0])) ]

    # If there are headers check if headers is larger than content
    if headers:
        columns_width = [ max(columns_width[i], len(header)) for i, header in enumerate(headers) ]

    # Add two extra spaces to columns_width for prettiness
    columns_width = [ w+2 for w in columns_width ]

    # Generate the row format string and delimiter string
    row_format = '  '.join(['{{:>{}}}'.format(w) for w in columns_width ])
    row_delim  = [ '='*w for w in columns_width ]

    # Print the headers if necessary
    print('')
    if headers:
        print(row_format.format(*headers))

    # Print the rows
    print(row_format.format(*row_delim))
    for row in rows:
        print(row_format.format(*row))
    print(row_format.format(*row_delim))


def int2ip(addr):
    return socket.inet_ntoa(struct.pack("<I", addr))

def ip2long(ip):
    packedIP = socket.inet_aton(ip)
    return struct.unpack("<L", packedIP)[0]

iplist = ['10.0.1.10', '10.0.4.10']

class SimpleSwitchApplication(eBPFCoreApplication):

    @set_event_handler(Header.HELLO)
    def hello(self, connection, pkt):
        self.mac_to_port = {}
        self.counter = {}

        with open('../examples/learningswitch_statistics.o', 'rb') as f:
            print("Installing the eBPF ELF")
            connection.send(InstallRequest(elf=f.read()))

    @set_event_handler(Header.NOTIFY)
    def notify_event(self, connection, pkt):
        ip, num_packets = struct.unpack('<II', pkt.data)

        if(int2ip(ip) in self.counter):
            ret_values = self.counter[int2ip(ip)]
            print int2ip(ip), (num_packets - ret_values[1])/(time.time() - ret_values[0])

        self.counter[int2ip(ip)] = (time.time(), num_packets)
        #print int2ip(ip), num_packets


if __name__ == '__main__':
    SimpleSwitchApplication().run()
