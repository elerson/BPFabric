#!/bin/bash

hashes=(3 5 7)
cols=(1000 2000 4000 8000 16000)
phi=(1000000 700000 400000 100000)

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


