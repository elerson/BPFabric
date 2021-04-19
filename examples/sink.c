#include <linux/if_ether.h>
#include <linux/ip.h>
#include "ebpf_switch.h"
#define BPF_MAP_TYPE_FOO 9
#define NUM_WORKERS 4


uint64_t prog(struct packet *pkt)
{

    //bpf_debug2(41, 41);
   
    return MULTICAST_PORT(DROP, DROP);
}
char _license[] SEC("license") = "GPL";
