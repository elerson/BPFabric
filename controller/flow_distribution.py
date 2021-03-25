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

class SimpleSwitchApplication(eBPFCoreApplication):

    @set_event_handler(Header.HELLO)
    def hello(self, connection, pkt):
        self.mac_to_port = {}
        self.counter = {}

        with open('../examples/flow_distribution.o', 'rb') as f:
            print("Installing the eBPF ELF")
            connection.send(InstallRequest(elf=f.read()))

        self.connection = connection
        self.last = 0
        self.request()


    def request(self):            
        self.connection.send(TableListRequest(table_name="flow_dist"))
        threading.Timer(10, self.request).start()

    @set_event_handler(Header.TABLE_LIST_REPLY)
    def table_list_reply(self, connection, pkt):
        entries = []

        if pkt.HasField('items') and pkt.HasField('entry'):
            if pkt.entry.table_type == TableDefinition.HASH:
                item_size = pkt.entry.key_size + pkt.entry.value_size
                fmt = "{}s{}s".format(pkt.entry.key_size, pkt.entry.value_size)

                for i in range(pkt.n_items):
                    key, value = struct.unpack_from(fmt, pkt.items, i * item_size)
                    v = struct.unpack('<I', value)
                    print(i, v)

            elif pkt.entry.table_type == TableDefinition.ARRAY:
                item_size = pkt.entry.value_size
                fmt = "{}s".format(pkt.entry.value_size)

                for i in range(pkt.n_items):
                    #struct.unpack('<I', pkt.data)
                    value = struct.unpack_from(fmt, pkt.items, i * item_size)[0]
                    v = struct.unpack('<I', value)
                    if(v[0] > 0):
                      print i, v[0]

if __name__ == '__main__':
    SimpleSwitchApplication().run()
