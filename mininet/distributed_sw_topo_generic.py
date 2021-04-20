#!/usr/bin/env python

from mininet.net import Mininet
from mininet.topo import Topo
from mininet.cli import CLI

from eBPFSwitch import eBPFSwitch, eBPFHost
from subprocess import check_output
import signal
import os
import threading
import sys

from time import sleep
import zmq
UDP_PORT=5543



class DistributedSwitchTopo(Topo):
    def __init__(self, **opts):
        # Initialize topology and default options
        Topo.__init__(self, **opts)
        self.N_LOAD_BALANCER = 3
        self.N_WORKERS = 4
	load_balancer_switches = []
	worker_switches = []
	hosts = []
	
	for i in range(self.N_WORKERS):
            switch = self.addSwitch('w'+str(i), switch_path="../softswitch/softswitch")  
            worker_switches.append(switch)
            pass
        
	sleep(1)
	
	for i in range(self.N_LOAD_BALANCER):
            switch = self.addSwitch('b'+str(i), switch_path="../softswitch/softswitch", switch_type=1)        
            load_balancer_switches.append(switch)
          
        

       
        for load_balancer in load_balancer_switches:
            for worker in worker_switches:
                self.addLink(load_balancer, worker)
                pass
        
        sink = self.addSwitch('s0', switch_path="../softswitch/softswitch", switch_type=3)
        for load_balancer in load_balancer_switches:
            self.addLink(load_balancer, sink)
           
         
        
        for i in range(self.N_LOAD_BALANCER):
            host = host = self.addHost('h%d' % (i + 1),
                                ip = "10.0.%d.10/24" % i,
                                mac = '00:04:00:00:00:%02x' %i)
            hosts.append(host)
        for i in range(self.N_LOAD_BALANCER):
             load_balancer = load_balancer_switches[i]
             host          = hosts[i]
             self.addLink(load_balancer, host) 
             
        
def exec_pcap(host):
   print "EXEC PCAP"
   host[0].cmd('./pcap.sh '+host[1] +' '+ host[2])

def main():


    
    memory_files = ['MVSKETCH', 'CUCKOOFILTER', 'MINCOUNT', 'KARY', 'ELASTIC_MAP', 'BITMAP']
    os.system("rm /tmp/SWITCH_TIME*")
    for mem_file in memory_files:
        os.system("rm /tmp/" + mem_file)
        
    
    topo = DistributedSwitchTopo()
    net = Mininet(topo = topo, host = eBPFHost, switch = eBPFSwitch, controller = None)
    net.start()
    
    sleep(3)
    context = zmq.Context()
    sock = context.socket(zmq.PUSH)
    sock.connect("tcp://localhost:%s" % UDP_PORT)
    
    data_file = sys.argv[1]
    MESSAGE = bytes('1-'+data_file)
    sock.send(MESSAGE)
    
    
    #time.sleep(5)
    #
    hosts = [(net.get('h1'), 'h1-eth0', '/media/elerson/dados/pcap/2016/worker0/ether-chicago-2016_0.pcap'),
             (net.get('h2'), 'h2-eth0', '/media/elerson/dados/pcap/2016/worker1/ether-chicago-2016_1.pcap'),
             (net.get('h3'), 'h3-eth0', '/media/elerson/dados/pcap/2016/worker2/ether-chicago-2016_2.pcap')]
    #hosts = [(net.get('h1'), 'h1-eth0', '/media/elerson/dados/pcap/2016/worker0/meta.json'),
    #         (net.get('h2'), 'h2-eth1', '/media/elerson/dados/pcap/2016/worker1/meta.json')]
    
    #hosts = [(net.get('h1'), 'h1-eth0', '/homeLocal2/elerson/redes/pcap/2016/worker0/ether-chicago-2016_0.pcap'),
    #         (net.get('h2'), 'h2-eth0', '/homeLocal2/elerson/redes/pcap/2016/worker1/ether-chicago-2016_1.pcap'),
    #         (net.get('h3'), 'h3-eth0', '/homeLocal2/elerson/redes/pcap/2016/worker2/ether-chicago-2016_2.pcap')]
    #
    #
    threads = []
    #print "EXEC PCAP B"
    for h in hosts:
        #print "EXEC PCAP B"
        t = threading.Thread(target=exec_pcap, args=(h, ))
        t.start()
        threads.append(t)
        #
        #h.cmd('./pcap.sh')
    for t in threads:
        t.join() 
    #h1 = net.get('h1')
    #h2 = net.get('h2') 
    #h3 = net.get('h3') 
    
    #result1 = h1.cmd('./pcap.sh')
    #result1 = h2.cmd('./pcap2.sh')
    #result1 = h3.cmd('./pcap3.sh')
    
    
    print 'finishing'
    
    proc_list = check_output(["pidof",'softswitch'])[0:-1].split(' ')
    for proc in proc_list:
       os.kill(int(proc), signal.SIGUSR1)
       
    #net.stop()
    
    print 'finishing'
    sleep(10)
    
    
    MESSAGE= bytes('0-END')
    sock.send(MESSAGE)
    print 'finshed'
    
    #CLI(net)
   
    

if __name__ == '__main__':
    main()
