#!/usr/bin/env python
import struct
import socket
import time, threading



from core import eBPFCoreApplication, set_event_handler, FLOOD
from core.packets import *
import time
import signal, sys
import atexit


def int2ip(addr):
    return socket.inet_ntoa(struct.pack("<I", addr))

def ip2long(ip):
    packedIP = socket.inet_aton(ip)
    return struct.unpack("<L", packedIP)[0]

iplist = ['10.0.1.10', '10.0.4.10']

UDP_IP = "127.0.0.1"
UDP_PORT = 5007

class SimpleSwitchApplication(eBPFCoreApplication):


    @set_event_handler(Header.HELLO)
    def hello(self, connection, pkt):
        self.mac_to_port = {}
        self.counter = {}

        #atexit.register(self.sigint_handler)
        self.file = open('testfile.txt','a') 
        self.last = 0
        self.num_calls = 1
        self.mean_ = 0
       

        try:
            self.sock
        except:
            t = threading.Thread(target=self.sigint_handler)           
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # UDP
            self.sock.bind((UDP_IP, UDP_PORT))
            t.start()
        

        with open('../examples/tp_heavyhitter_2.o', 'rb') as f:
            print("Installing the eBPF ELF")
            connection.send(InstallRequest(elf=f.read()))

        self.connection = connection
        


    @set_event_handler(Header.NOTIFY)
    def notify_event(self, connection, pkt):
        ip, count_real, count_sketch,hashes, cols, phi, lasttime = struct.unpack('<IIII', pkt.data)
        
        self.mean_ += float(count_real-count_sketch)/count_real
        self.num_calls +=1

    def sigint_handler(self):

        while True:
            data, addr = self.sock.recvfrom(1024) # buffer size is 1024 bytes
            print(self.mean_/self.num_calls, 'test')
            self.file.write (str(self.mean_/self.num_calls)+'\n')
            self.num_calls = 1
            self.mean_ = 0

        #sys.exit()
        # if(not int2ip(ip) in self.counter):
        #     #ret_values = self.counter[int2ip(ip)]
        #     print (int2ip(ip), num_packets)
        #     self.counter[int2ip(ip)] = (time.time(), num_packets)
        #print int2ip(ip), num_packets


if __name__ == '__main__':
    SimpleSwitchApplication().run()
