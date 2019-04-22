#!/bin/bash
sleep 5
cd ../../sistemasredes
tcpreplay -i h1-eth0 equinix-chicago.dirA.20130815-125710.UTC.anon.pcap 
