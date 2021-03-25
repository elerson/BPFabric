#!/bin/bash

rows=(20 30 40)
cols=(100 500 1000 1500 2000 2500)
phi=(10000 40000 70000 100000)

for rows_ in ${rows[@]}; do
  for cols_ in ${cols[@]}; do
    for phi_ in ${phi[@]}; do
	./create_exp_heavychange.py $cols_ $rows_ $phi_
	make
	sudo mn -c
	sudo killall softswitch
	cd mininet
	sudo python 1sw_topo_test.py
	cd ..
    done
  done
done


