#!/usr/bin/env python
import struct

from core import eBPFCoreApplication, set_event_handler, FLOOD
from core.packets import *

import socket
import fcntl, os
import time, threading
import time
import signal, sys
import atexit
import os
import json
import os.path
import glob

import zmq
UDP_PORT=5543



memory_files = ['MVSKETCH', 'CUCKOOFILTER', 'MINCOUNT', 'KARY', 'ELASTIC_MAP', 'BITMAP']


class SimpleSwitchApplication(eBPFCoreApplication):

    @set_event_handler(Header.HELLO)
    def hello(self, connection, pkt):
        self.mac_to_port = {}
        
        self.count_sketch = 0
        self.hashes = 0
        self.cols = 0
        self.phi = 0
        self.lasttime = 0
        self.ni_data = {}
        try:
            self.sock
        except:
            t = threading.Thread(target=self.sigint_handler)
            
            self.sock = 1# context.socket(zmq.REP)
            #self.sock.bind("tcp://*:%s" % UDP_PORT)

            #self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # UDP
            #self.sock.bind((UDP_IP, UDP_PORT))
            #self.sock.setblocking(0)
            #fcntl.fcntl(self.sock, fcntl.F_SETFL, os.O_NONBLOCK)
            t.start()
        
        
        self.data = {}
        self.data_id = {}
        
        if(pkt.type == 1):
            with open('../examples/load_balancer.o', 'rb') as f:
                print("Installing the eBPF ELF - LOAD BALANCER")
                connection.send(InstallRequest(elf=f.read()))
        elif(pkt.type == 0):
            with open('../examples/generic_program.o', 'rb') as f:
                print("Installing the eBPF ELF - CONTROLLER")
                connection.send(InstallRequest(elf=f.read()))
        elif(pkt.type == 3):
            with open('../examples/sink.o', 'rb') as f:
                print("Installing the eBPF ELF - SINK")
                connection.send(InstallRequest(elf=f.read()))
             
    @set_event_handler(Header.NOTIFY)
    def notify_event(self, connection, pkt):
        
        if(pkt.id == 2):
            if int(pkt.dpid) not in self.data:
                self.data[int(pkt.dpid)] = []
                self.data_id[int(pkt.dpid)] = (0, 0)
                
            data = struct.unpack('@' + (len(pkt.data)/4)*'I', pkt.data)
            print('new data', pkt.dpid, len(data)/4)
            if len(pkt.data) == 0:
                self.data[int(pkt.dpid)].append([0, self.data_id[int(pkt.dpid)]])
                
            #print('new data', pkt.dpid, data)
            for ip_ in data:
                self.data[int(pkt.dpid)].append([ip_, self.data_id[int(pkt.dpid)]])
            return
    
    
        ip_, hashes, cols, phi, rows, lasttime, stage, dst0, dst1, dst2 = struct.unpack('@IIIIIIIQQQ', pkt.data)
        
        #print(pkt.dpid, pkt.id, ip_)
        if(int(pkt.dpid) not in self.data):
            self.data_id[int(pkt.dpid)] = (0, 0, 0)
            self.data[int(pkt.dpid)] = []
        
        if(pkt.id == 1):
            print('1 data', int(pkt.dpid), lasttime)
            self.stage = stage
            self.hashes = hashes
            self.cols = cols
            self.phi = phi
            self.rows = rows
            self.data_id[int(pkt.dpid)] = (dst0, dst1, dst2)
            
            for ip_ in self.ni_data[int(pkt.dpid)]:
                self.data[int(pkt.dpid)].append([ip_, self.data_id[int(pkt.dpid)]])
                
            self.ni_data[int(pkt.dpid)] = []
            
        else:
            print(pkt.dpid, ip_, self.data_id[int(pkt.dpid)])
            if int(pkt.dpid) not in self.ni_data:
            	self.ni_data[int(pkt.dpid)] = []
            	
            self.ni_data[int(pkt.dpid)].append(ip_)
            self.lasttime = lasttime
            #self.data[int(pkt.dpid)].append([ip_, self.data_id[int(pkt.dpid)]])
        
    @set_event_handler(Header.PACKET_IN)
    def packet_in(self, connection, pkt):
        metadatahdr_fmt = 'I10x'
        ethhdr_fmt = '>6s6sH'

        in_port, = struct.unpack_from(metadatahdr_fmt, pkt.data, 0)
        eth_dst, eth_src, eth_type = struct.unpack_from(ethhdr_fmt, pkt.data, struct.calcsize(metadatahdr_fmt))
    
    def getExecutionTime(self):
        exec_data = []
        for fname in glob.glob("/tmp/SWITCH_TIME*"):
             print(file)
             file_ = open(fname, 'r')
             line = file_.readline().split(' ')
             exec_data.append((fname.split('/')[2], line))
             print(fname.split('/')[2], line)
        return exec_data
             
    def getMemory(self):
        memory_data = []
        for file_name in memory_files:
            fname = '/tmp/' + file_name
            if os.path.isfile(fname):
                file_ = open(fname, 'r')
                line = file_.readline()
                memory_data.append((file_name, line))
                print(file_name, line)
        return memory_data
    
    def sigint_handler(self):
        context = zmq.Context()
        sock = context.socket(zmq.PULL)
        sock.bind("tcp://*:%s" % UDP_PORT)
        
        while True:
            rcv_data = str(sock.recv())#(1024) # buffer size is 1024 bytes
            
            if(rcv_data[0] == '1'):
                rcv_str = rcv_data.split('-')[1].split('.')[0]
                #print(rcv_data.split('-'))
                PREFIX= rcv_str.split('#')[0]
                DIR = os.getcwd()+'/'+rcv_str.split('#')[1]+'/'
                print('dir', DIR, PREFIX)
                try:
                    os.mkdir(DIR)
                except:
                    pass
                continue
            
            mem_ = self.getMemory()
            exec_time = self.getExecutionTime()
            more_info = [self.hashes, self.cols, self.phi, self.rows]
            
            name_  = 'data_'+PREFIX+str(self.hashes)+'_'+ str(self.cols) +'_'+ str(self.rows) +'_'+ str(self.phi) +'_';
            files_ = glob.glob(DIR + name_ + '*')
            print('files', files_)
            file_name = DIR + name_ +str(1+len(files_))+'.json'
            
            self.data['info'] = {"memory": mem_, "exec_time": exec_time, "more": more_info}
            with open(file_name, 'w') as fp:
                json.dump(self.data, fp)
                print(len(self.data.keys()), 'saved')

            self.data = {}
            time.sleep(1)


def signal_handler(sig, frame):
    print('You pressed Ctrl+C!')
    os.kill(os.getpid(),signal.SIGKILL)

if __name__ == '__main__':

    #data = sock.recv()
    #print(data)
    signal.signal(signal.SIGINT, signal_handler)
    SimpleSwitchApplication().run()
