#!/bin/bash

hashes=(3)
cols=(500 1000 2000 4000 8000 16000)
rows=(10 20 30)
phis=(200)
types=(BPF_MAP_TYPE_KARY BPF_MAP_TYPE_MINCOUNT)
times=(1)
num_heavys=(1000)
repetitions=(1)
#
#('data_MINCOUNT_1000_1_3_8000_10_200_1.json', [[u'MINCOUNT', u'320000'], [u'BITMAP', u'150080']], 0.8270365900600926)
#('data_KARY_1000_1_3_8000_10_200_1.json', [[u'KARY', u'640000'], [u'BITMAP', u'150080']], 0.7493015525600645)

hashes=(3)
cols=(8000)
rows=(10)
phis=(200)
types=(BPF_MAP_TYPE_KARY BPF_MAP_TYPE_MINCOUNT)
times=(1)
num_heavys=(1000)
repetitions=(1)
workers=(1 2 4 8 16)

for worker in ${workers[@]}; do  
  for hash in ${hashes[@]}; do
    for col in ${cols[@]}; do
      for row in ${rows[@]}; do
        for phi in ${phis[@]}; do
          for type_ in ${types[@]}; do
            for time_ in ${times[@]}; do
              for num_heavy in ${num_heavys[@]}; do
                for rep in ${repetitions[@]}; do
                   python2.7 create_exp_generic.py examples/templates/journal_heavyhitter_type_1_NI.c ___COLS___ $col ___ROWS___ $row ___HASHES___ $hash ___PHI___ $phi ___MAP___ $type_ ___NUM_HEAVY___ $num_heavy __TIME__ $time_
                   python2.7 create_exp_generic_load_balancer.py examples/templates/load_balancer.c ___WORKERS___ $worker
                   make
                   mn -c
                   killall softswitch
                   cd mininet
                   python2.7 distributed_sw_topo_generic.py "${type_}_${num_heavy}_${time_}_${worker}_#journal_heavyhitter_type_1_NI.c" "${worker}"
                   cd ..
                   #echo "${type_}_${num_heavy}_${time_}_#journal_heavyhitter_type_1_IV.c" 
                done
              done
            done
           done
        done
      done
    done
  done
done



#python2.7 create_exp_generic.py examples/templates/journal_heavyhitter_type_1_IV.c ___COLS___ 10 ___ROWS___ 100 ___HASHES___ 2 ___PHI___ 100 ___MAP___ ELASTIC ___NUM_HEAVY___ 1000 __TIME__ 2
