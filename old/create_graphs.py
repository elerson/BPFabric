import glob
import json

ground_truth_dir = '/home/elerson/Documents/BPFabric/teste/*heavychange.json'
experiments_dir = '/home/elerson/Documents/BPFabric/controller/heavychangeproc/*.json'

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


fig = plt.figure()
ax  = plt.axes()

x = sorted(list(all_cols))
ax.set_xticks(sorted(x))
line_style = [':b', '-g', 'r', '-.p']
l = 0
plt.ylim((0,4))
plt.title('False positives x Column size')
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


plt.xlabel('number of columns in the sketch')
plt.ylabel('False Positives (x true values)')    


plt.legend()
plt.savefig('heavy_change_false_positive1.png')


#grafico2

fig = plt.figure()
ax  = plt.axes()

x = sorted(list(all_rows))
ax.set_xticks(sorted(x))
line_style = [':b', '-g', 'r', '-.p']
l = 0
plt.ylim((0,4))
plt.title('False positives x Row size (number of hashes)')
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


plt.xlabel('number of rows in the sketch')
plt.ylabel('False Positives (x true values)')    


plt.legend()
#plt.show()
plt.savefig('heavy_change_false_positive2.png')




#grafico 1
import matplotlib.pyplot as plt
import numpy as np
import math


fig = plt.figure()
ax  = plt.axes()

x = sorted(list(all_cols))
ax.set_xticks(sorted(x))
line_style = [':b', '-g', 'r', '-.p']
l = 0
plt.ylim((0,2))
plt.title('True Positives x Column size')
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


plt.xlabel('number of columns in the sketch')
plt.ylabel('True Positives (x true values)')    


plt.legend()
plt.savefig('heavy_change_true_positive1.png')


#grafico2

fig = plt.figure()
ax  = plt.axes()

x = sorted(list(all_rows))
ax.set_xticks(sorted(x))
line_style = [':b', '-g', 'r', '-.p']
l = 0
plt.ylim((0,2))
plt.title('True Positives x Row size (number of hashes)')
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


plt.xlabel('number of rows in the sketch')
plt.ylabel('True Positives (x true values)')    


plt.legend()
#plt.show()
plt.savefig('heavy_change_true_positive2.png')


#flow distribution grah

import csv
with open('traffic_count.csv', 'r') as f:
    reader = csv.reader(f)    
    table = list(reader)

table_ =  map(lambda s: map(float, s), table)

x = [128, 256, 512, 1024, 2048]

fig = plt.figure()
ax  = plt.axes()

ax.set_xticks(sorted(x))
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

plt.xlabel('number of rows in the sketch')
plt.ylabel('Error %')    


plt.legend()
plt.savefig('traffic_count.png')


# distribution

import csv
from math import log
import matplotlib.pyplot as plt
import numpy as np
import math

with open('distribution.csv', 'r') as f:
    reader = csv.reader(f)    
    table = list(reader)

table_ =  map(lambda s: map(int, s), table)
x = map(lambda s: s[0]*7, table_)
y = map(lambda s: s[1], table_)


fig = plt.figure()
ax  = plt.axes()

plt.title('Histogram of flow distribution')
plt.bar(x, height=y)

plt.ylabel('number of packets')
plt.xlabel('packets size (bytes)')  

plt.legend()
plt.savefig('flow_distribution.png')
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
import matplotlib.pyplot as plt
import numpy as np
import math


fig = plt.figure()
ax  = plt.axes()

x = sorted(list(all_cols))
ax.set_xticks(sorted(x))
line_style = [':b', '-g', 'r', '-.p']
l = 0
#plt.ylim((0,2))
plt.title('False Positives x Column Size')
for phi in sorted(list(all_phis)):
    y = []
    for cols in sorted(x):
        a = set(map(str, experiments_data[(max(all_rows), cols, phi)].keys()))
        b = set(map(str, ground_truth[phi].keys()))
        print(len(a.intersection(b)), len(b))
        #
        real = float(len(ground_truth[phi].keys()))
        found = float(len(experiments_data[(max(all_rows), cols, phi)].keys()))
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


plt.xlabel('number of columns in the sketch')
plt.ylabel('False positives (x true values)')    


plt.legend()
plt.savefig('heavy_hitter1.png')



#grafico2

fig = plt.figure()
ax  = plt.axes()

x = sorted(list(all_rows))
ax.set_xticks(sorted(x))
line_style = [':b', '-g', 'r', '-.p']
l = 0
#plt.ylim((0,2))
plt.title('False Positives x Row size (number of hashes)')
for phi in sorted(list(all_phis)):
    y = []
    for row in sorted(x):
        a = set(map(str, experiments_data[(row, max(all_cols), phi)].keys()))
        b = set(map(str, ground_truth[phi].keys()))
        #
        real = float(len(ground_truth[phi].keys()))
        found = float(len(experiments_data[(max(all_rows), cols, phi)].keys()))
        erro1 = abs(found-real)/real
        error2 = (len(a) - len(a.intersection(b)))/float(len(b))
        #
        y.append(error2)
    #
    legend = str('phi='+str(phi))
    print(y)
    plt.plot(x, y, line_style[l],label=legend)
    l += 1


plt.xlabel('number of rows in the sketch')
plt.ylabel('False positives (x true values)')    


plt.legend()
#plt.show()
plt.savefig('heavy_hitter2.png')








phi = ground_truth.keys()[1]

a = set(map(str, (ground_truth[phi].keys())))
b = set(map(str, experiments_data[(3, 1000, phi)]))

a.intersection(b)



