#!/usr/bin/env python
import struct
import socket
import time, threading



from core import eBPFCoreApplication, set_event_handler, FLOOD
from core.packets import *
import time
import signal, sys
import atexit

import json



def int2ip(addr):
    return socket.inet_ntoa(struct.pack("<I", addr))

def ip2long(ip):
    packedIP = socket.inet_aton(ip)
    return struct.unpack("<L", packedIP)[0]

iplist = ['10.0.1.10', '10.0.4.10']

UDP_IP = "127.0.0.1"
UDP_PORT = 50005

class SimpleSwitchApplication(eBPFCoreApplication):


    @set_event_handler(Header.HELLO)
    def hello(self, connection, pkt):
        self.mac_to_port = {}
        self.counter = {}

        #atexit.register(self.sigint_handler)
        self.file = open('heavyhitter.txt','a') 
        self.last = 0
        self.num_calls = 1
        self.mean_ = 0
        self.hashes_ = 0
        self.cols_   = 0
        self.phi_    = 0


        self.count_real_ = {}
        self.count_sketch_ = {}   

        try:
            self.sock
        except:
            t = threading.Thread(target=self.sigint_handler)           
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # UDP
            self.sock.bind((UDP_IP, UDP_PORT))
            t.start()
        

        with open('../examples/tp_heavyhitter_3.o', 'rb') as f:
            print("Installing the eBPF ELF")
            connection.send(InstallRequest(elf=f.read()))

        self.connection = connection
        


    @set_event_handler(Header.NOTIFY)
    def notify_event(self, connection, pkt):
        ip_, count_sketch, hashes, cols, phi, lasttime = struct.unpack('<IIIIII', pkt.data)
        
        ip = int2ip(ip_)
        try:
            if(count_sketch > phi):
                self.count_sketch_[ip] = max(self.count_sketch_[ip], count_sketch)
        except:
            if(count_sketch > phi):
                self.count_sketch_[ip] = count_sketch
                print('new', len(self.count_sketch_.keys()))

        self.cols_   = cols
        self.phi_    = phi
        self.hashes_ = hashes

    def sigint_handler(self):

        while True:
            data, addr = self.sock.recvfrom(1024) # buffer size is 1024 bytes
            print(self.mean_/self.num_calls, 'test')
            self.file.write (str(self.cols_)+','+ str(self.phi_) +','+ str(self.hashes_)+',' +str(len(self.count_sketch_.keys())) +'\n')
            self.file.flush()

            with open(str(self.hashes_)+'_'+str(self.cols_)+'_'+str(self.phi_)+'_heavyhitter.json', 'w') as fp:
                json.dump(self.count_sketch_, fp)
                print(len(self.count_sketch_.keys()), 'saved')

            self.count_sketch_ = {}


if __name__ == '__main__':
    SimpleSwitchApplication().run()
