#!/usr/bin/env python
# -*- coding: utf-8 -*- 
from __future__ import unicode_literals

import glob
import json

ground_truth_dir = '/home/elerson/Documents/BPFabric/teste/*heavychange.json'
experiments_dir = '/home/elerson/Documents/BPFabric/controller/heavychange2/*.json'

ground_truth_files = glob.glob(ground_truth_dir)
experiments_files = glob.glob(experiments_dir)

ground_truth = {}
for file in ground_truth_files:
    phi = int(file.split('/')[-1].split('_')[0])
    with open(file) as f:
        ground_truth[phi] = json.load(f)

experiments_data = {}
for file in experiments_files:
    #
    rows = int(file.split('/')[-1].split('_')[0])
    cols = int(file.split('/')[-1].split('_')[1])
    phi  = int(file.split('/')[-1].split('_')[2])
    with open(file) as f:
        experiments_data[(rows, cols, phi)] = json.load(f)

all_rows = set(map( lambda s: s[0] ,experiments_data.keys()))
all_cols = set(map( lambda s: s[1] ,experiments_data.keys()))
all_phis = set(map( lambda s: s[2] ,experiments_data.keys()))

#grafico 1
import matplotlib.pyplot as plt
import numpy as np
import math
plt.rcParams['axes.labelweight']= 'bold'
plt.rcParams['axes.labelsize']  = 'x-large'
plt.rcParams['figure.figsize']  = (8, 6.5)
plt.rcParams['ytick.labelsize'] = 'x-large'
plt.rcParams['xtick.labelsize'] = 'x-large'

# params = {'legend.fontsize': 'x-large',
#           'figure.figsize': (15, 5),
#          'axes.labelsize': 'x-large',
#          'axes.titlesize':'x-large',
#          'xtick.labelsize':'x-large',
#          'ytick.labelsize':'x-large'}
# pylab.rcParams.update(params)


fig = plt.figure()
ax  = plt.axes()
#plt.rcParams['axes.labelsize'] = 16


x = sorted(list(all_cols))
ax.set_xticks(sorted(x))
line_style = [':b', '-g', 'r', '-.p']
l = 0
plt.ylim((0,2))
#plt.title('Falsos Positivos Vs Número de Colunas')
for phi in sorted(list(all_phis)):
    y = []
    for cols in sorted(x):
        a = set(experiments_data[(max(all_rows), cols, phi)].keys())
        b = set(ground_truth[phi].keys())
        #
        real = float(len(ground_truth[phi].keys()))
        found = float(len(experiments_data[(max(all_rows), cols, phi)].keys()))
        erro1 = abs(found-real)/real
        error2 = abs(len(a)-len(a.intersection(b)))/float(len(b))
        print(len(a.intersection(b)) - len(b), len(a.intersection(b)), len(b))
        #
        #
        y.append(error2)
        #
    legend = str('phi='+str(phi))
    print(y)
    plt.plot(x, y, line_style[l],label=legend)
    l += 1


plt.xlabel('Número de Colunas no sketch')
plt.ylabel('Falsos Positivos (x Valores Positivos)')    


plt.legend()

plt.savefig('heavy_change_false_positive1.pdf')
#plt.savefig('hc_fp.pdf')


#grafico2

fig = plt.figure()
ax  = plt.axes()

x = sorted(list(all_rows))
ax.set_xticks(sorted(x))
line_style = [':b', '-g', 'r', '-.p']
l = 0
plt.ylim((0,2))
#plt.title('Falsos Positivos x Número de Linhas (Número de Hashes)')
for phi in sorted(list(all_phis)):
    y = []
    for row in sorted(x):
        a = set(experiments_data[(row, max(all_cols), phi)].keys())
        b = set(ground_truth[phi].keys())
        #
        real = float(len(ground_truth[phi].keys()))
        found = float(len(experiments_data[(max(all_rows), cols, phi)].keys()))
        erro1 = abs(found-real)/real
        error2 = abs(len(a.intersection(b)) - len(a))/float(len(b))
        #
        y.append(error2)
    #
    legend = str('phi='+str(phi))
    print(y)
    plt.plot(x, y, line_style[l],label=legend)
    l += 1


plt.xlabel('Número de Linhas no Sketch')
plt.ylabel('Falsos Positivos (x Valores Positivos)')    


plt.legend()
#plt.show()
plt.savefig('heavy_change_false_positive2.pdf')




#grafico 1
#import matplotlib.pyplot as plt
import numpy as np
import math


fig = plt.figure()
ax  = plt.axes()

x = sorted(list(all_cols))
ax.set_xticks(sorted(x))
line_style = [':b', '-g', 'r', '-.p']
l = 0
plt.ylim((0,2))
#plt.title('Verdadeiros Positivos x Número de Colunas')
for phi in sorted(list(all_phis)):
    y = []
    for cols in sorted(x):
        a = set(experiments_data[(max(all_rows), cols, phi)].keys())
        b = set(ground_truth[phi].keys())
        #
        real = float(len(ground_truth[phi].keys()))
        found = float(len(experiments_data[(max(all_rows), cols, phi)].keys()))
        erro1 = abs(found-real)/real
        error2 = abs(len(a.intersection(b)))/float(len(b))
        print(len(a.intersection(b)) - len(b), len(a.intersection(b)), len(b))
        #
        #
        y.append(error2)
        #
    legend = str('phi='+str(phi))
    print(y)
    plt.plot(x, y, line_style[l],label=legend)
    l += 1


plt.xlabel('Número de Colunas no Sketch')
plt.ylabel('Verdadeiros Positivos (x Valores Verdadeiros)')    


plt.legend()
plt.savefig('heavy_change_true_positive1.pdf')


#grafico2

fig = plt.figure()
ax  = plt.axes()

x = sorted(list(all_rows))
ax.set_xticks(sorted(x))
line_style = [':b', '-g', 'r', '-.p']
l = 0
plt.ylim((0,2))
#plt.title('Verdadeiros Positivos Vs Número de Linhas (Número de Hashes)')
for phi in sorted(list(all_phis)):
    y = []
    for row in sorted(x):
        a = set(experiments_data[(row, max(all_cols), phi)].keys())
        b = set(ground_truth[phi].keys())
        #
        real = float(len(ground_truth[phi].keys()))
        found = float(len(experiments_data[(max(all_rows), cols, phi)].keys()))
        erro1 = abs(found-real)/real
        error2 = abs(len(a.intersection(b)))/float(len(b))
        #
        y.append(error2)
    #
    legend = str('phi='+str(phi))
    print(y)
    plt.plot(x, y, line_style[l],label=legend)
    l += 1


plt.xlabel('Número de Linhas no sketch')
plt.ylabel('Verdadeiros Positivos (x Valores Verdadeiros)')    


plt.legend()
#plt.show()
plt.savefig('heavy_change_true_positive2.pdf')


#flow distribution grah
#
import csv
with open('traffic_count.csv', 'r') as f:
    reader = csv.reader(f)    
    table = list(reader)

table_ =  map(lambda s: map(float, s), table)

x = [128, 256, 512, 1024, 2048]

fig = plt.figure()
ax  = plt.axes()


line_style = [':b', '-g', 'r', '-.p', '-b', '-g', 'r', '-.p']
l = 0
for j in range(len(x)):
    y = []
    for i in range(len(table_)):
        y.append(table_[i][j])
    print(y)
    #
    legend = str('bits(x32)='+str(x[j]))
    print(y)
    plt.plot(y, line_style[l],label=legend)
    l += 1

plt.xlabel('Tempo (s)')
plt.ylabel('Erro %')    

#ax.set_xticks(sorted(x))
plt.legend()
#plt.show()
plt.savefig('traffic_count.pdf')


# distribution

import csv
from math import log
#import matplotlib.pyplot as plt
import numpy as np
import math

with open('distribution.csv', 'r') as f:
    reader = csv.reader(f)    
    table = list(reader)

table_ =  map(lambda s: map(int, s), table)
x = map(lambda s: s[0]*7, table_)
y = map(lambda s: s[1], table_)
y = np.array(y)/1000
y = y.tolist()


fig = plt.figure()
ax  = plt.axes()

#plt.title('Histograma de Distribuição do Fluxo')
plt.bar(x, height=y)

plt.ylabel('Número de Pacotes (x1000)')
plt.xlabel('Tamanho do Pacote (bytes)')  

plt.legend()
plt.savefig('flow_distribution.pdf')
#plt.show()


#heavy hitter

import glob
import json

ground_truth_dir = '/home/elerson/Documents/BPFabric/teste/*heavyhitter.json'
experiments_dir = '/home/elerson/Documents/BPFabric/controller/heavyhitter/*.json'

ground_truth_files = glob.glob(ground_truth_dir)
experiments_files = glob.glob(experiments_dir)

ground_truth = {}
for file in ground_truth_files:
    phi = int(file.split('/')[-1].split('_')[0])
    with open(file) as f:
        ground_truth[phi] = json.load(f)

experiments_data = {}
for file in experiments_files:
    #
    rows = int(file.split('/')[-1].split('_')[0])
    cols = int(file.split('/')[-1].split('_')[1])
    phi  = int(file.split('/')[-1].split('_')[2])
    with open(file) as f:
        experiments_data[(rows, cols, phi)] = json.load(f)

all_rows = set(map( lambda s: s[0] ,experiments_data.keys()))
all_cols = set(map( lambda s: s[1] ,experiments_data.keys()))
all_phis = set(map( lambda s: s[2] ,experiments_data.keys()))


#grafico 1 heavyhitter
#import matplotlib.pyplot as plt
import numpy as np
import math

#plt.rcParams['xtick.labelsize'] = 'medium'
fig = plt.figure()
ax  = plt.axes()

x = sorted(list(all_cols))
x = np.array(x)/1000
x = x.tolist()
ax.set_xticks(sorted(x))
line_style = [':b', '-g', 'r', '-.p']
l = 0
#plt.ylim((0,2))
#plt.title('Falsos Positivos x Número de Colunas')
for phi in sorted(list(all_phis)):
    y = []
    for cols in sorted(x):
        a = set(map(str, experiments_data[(max(all_rows), cols*1000, phi)].keys()))
        b = set(map(str, ground_truth[phi].keys()))
        print(len(a.intersection(b)), len(b))
        #
        real = float(len(ground_truth[phi].keys()))
        found = float(len(experiments_data[(max(all_rows), cols*1000, phi)].keys()))
        erro1 = abs(found-real)/real
        error2 = (len(a) - len(a.intersection(b)))/float(len(b))
        
        #
        #
        y.append(error2)
        #
    legend = str('phi='+str(phi))
    print(y)
    plt.plot(x, y, line_style[l],label=legend)
    l += 1


plt.xlabel('Número de Colunas no Sketch (x1000)')
plt.ylabel('Falsos Positivos (x Valores Verdadeiros)')    


plt.legend()
plt.savefig('heavy_hitter1.pdf')
#plt.rcParams['xtick.labelsize'] = 'x-large'



#grafico2

fig = plt.figure()
ax  = plt.axes()

x = sorted(list(all_rows))
ax.set_xticks(sorted(x))
line_style = [':b', '-g', 'r', '-.p']
l = 0
#plt.ylim((0,2))
#plt.title('Falsos Positivos Vs Número de Linhas (Número de Hashes)')
for phi in sorted(list(all_phis)):
    y = []
    for row in sorted(x):
        a = set(map(str, experiments_data[(row, max(all_cols), phi)].keys()))
        b = set(map(str, ground_truth[phi].keys()))
        #
        real = float(len(ground_truth[phi].keys()))
        found = float(len(experiments_data[(max(all_rows), cols*1000, phi)].keys()))
        erro1 = abs(found-real)/real
        error2 = (len(a) - len(a.intersection(b)))/float(len(b))
        #
        y.append(error2)
    #
    legend = str('phi='+str(phi))
    print(y)
    plt.plot(x, y, line_style[l],label=legend)
    l += 1


plt.xlabel('Número de Linhas no Sketch')
plt.ylabel('Falsos Positivos (x Valores Verdadeiros)')    


plt.legend()
#plt.show()
plt.savefig('heavy_hitter2.pdf')








phi = ground_truth.keys()[1]

a = set(map(str, (ground_truth[phi].keys())))
b = set(map(str, experiments_data[(3, 1000, phi)]))

a.intersection(b)



