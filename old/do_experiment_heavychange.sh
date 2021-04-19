#!/bin/bash

rows=(20)
cols=(100)
phi=(10000)

for rows_ in ${rows[@]}; do
  for cols_ in ${cols[@]}; do
    for phi_ in ${phi[@]}; do
	./create_exp_heavychange.py $cols_ $rows_ $phi_
	make
	sudo mn -c
	sudo killall softswitch
	cd mininet
	sudo python2.7 1sw_topo_test.py
	cd ..
    done
  done
done


