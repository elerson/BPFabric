import glob
import json
import dpkt
from dpkt.utils import mac_to_str, inet_to_str
NUM_WORKERS = 4
PHI_        = 100.0


def bytes_to_int(bytes):
    #print(bytes)
    result = ord(bytes[0])
    result = result << 8;
    result = result | (ord(bytes[1]))
    result = result << 8;
    result = result | (ord(bytes[2]))
    result = result << 8;
    result = result | (ord(bytes[3]))
    
    return result


def bytes_to_int_reverse(bytes):
    #print(bytes)
    result = ord(bytes[3])
    result = result << 8;
    result = result | (ord(bytes[2]))
    result = result << 8;
    result = result | (ord(bytes[1]))
    result = result << 8;
    result = result | (ord(bytes[0]))
    return result

def get_mac(bytes):
   result = 0
   for i in range(6):
      result = result << 8
      result = result | (ord(bytes[i]))
   return result

def getID(id):
  return ((id >> 8) & 0x00FF) | ((id << 8) & 0xFF00) 

pcap_dir = '/home/elerson/Documents/BPFabric2/mininet/test.pcap'
data_dir = 'controller/heavyhitter.json'

with open(data_dir) as f:
   data = json.load(f)

lb_num_map = {}
for key in data.keys():
  if(data[key] == []):
      lb_num_map[key] = 0
      continue
  print(data[key][0])
  lb_num_map[key] = data[key][0][0]%NUM_WORKERS

analisys_data = {}
for lb in data:
   lb_num = lb_num_map[lb]
   analisys_data[lb_num] = {}
   for d in data[lb]:
      ip_ = d[0]
      src,dst = d[6]
      key = (src, dst)
      if key not in analisys_data[lb_num]:
         analisys_data[lb_num][key] = set()
      
      #print(key)
      analisys_data[lb_num][key].add(ip_)


 
f = open(pcap_dir)
pcap = dpkt.pcap.Reader(f)


count_hitter = {}
total_result = 0
total_gt = 0
total_false_positive = 0
total_false_negative = 0
total_true_positive = 0

i = 0
for ts, buf in pcap:
   
   eth = dpkt.ethernet.Ethernet(buf)
   if not isinstance(eth.data, dpkt.ip.IP):
      continue
   
   key = (get_mac(eth.src), get_mac(eth.dst))
   #print(key, ts)
   for worker in analisys_data:
   
      if key in analisys_data[worker]:
         result_ = analisys_data[worker][key]
         gt_ = set()
         if worker in count_hitter:
            for ip in count_hitter[worker]:
               if count_hitter[worker][ip] > PHI_:
	          gt_.add(ip)
        
         count_hitter[worker] = {}
         if(len(gt_) > 0):
            total_result += float(len(gt_.intersection(result_)))
            total_gt += len(gt_)
            
            false_positive = result_-gt_
            false_negative = gt_-result_
            true_positive = gt_.intersection(result_)
            
            total_false_positive += len(false_negative)
            total_false_negative += len(false_positive)
            total_true_positive += len(true_positive)

            
            precision = float(len(true_positive))/(len(true_positive) + len(false_positive) )
            accuracy = float(len(true_positive))/(len(gt_))
            recall = float(len(true_positive))/(len(true_positive) + len(false_negative) )
            
            f1 = 2*precision*recall/(precision + recall + 0.001)
            
            
            total_precision = float(total_true_positive)/(total_true_positive+ total_false_positive )
            total_recall = float(total_true_positive)/(total_true_positive + total_false_negative)
            total_f1 = 2*total_precision*total_recall/(total_precision + total_recall + 0.0001)
            
            print(key, worker, accuracy, total_precision, total_f1)
      
   ip = eth.data
   ip_src = bytes_to_int_reverse(ip.src)
   worker = ip_src % NUM_WORKERS
   
   if(worker not in count_hitter):
      count_hitter[worker] = {}
      
   if ip_src not in count_hitter[worker]:
      count_hitter[worker][ip_src] = 0
   count_hitter[worker][ip_src] += 1



f.close()

   
   
