#!/bin/bash

hashes=(3 5 7)
cols=(100 500 1000 1500 2000 2500)
phi=(100000000 70000000 40000000 10000000)

for hashes_ in ${hashes[@]}; do
  for cols_ in ${cols[@]}; do
    for phi_ in ${phi[@]}; do
	./create_exp_heavyhitter.py $cols_ $hashes_ $phi_
	make
	sudo mn -c
	sudo killall softswitch
	cd mininet
	sudo python 1sw_topo_test.py
	cd ..
    done
  done
done


