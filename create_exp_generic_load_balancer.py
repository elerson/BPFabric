#!/usr/bin/env python

import sys
import os
import math

with open(sys.argv[1], 'r') as file:
  exp_str = file.read()

class Create():
  def create(self, params):
    with open("examples/generic_load_balancer.c", 'w') as f:
      str_ = exp_str
      for param in params:
         str_ = str_.replace(param, params[param])
      f.write(str_)


if __name__ == "__main__":

  num_params = len(sys.argv)-2
  params = {}
  
  i = 2
  while i <= num_params:
     params[sys.argv[i]] = sys.argv[i+1]
     i += 2
  print (params)
  
  #cols = int(sys.argv[1])
  #rows     = float(sys.argv[2])
  #phi     = float(sys.argv[3])
  exp = Create()
  exp.create(params)

