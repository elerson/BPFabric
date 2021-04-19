#!/bin/bash
#sleep 5
#cd ../../sistemasredes h1-eth0 
tcpreplay --duration=10 -i $1 $2
#gopherCap replay --out-interface $1 --dump-json $2 
