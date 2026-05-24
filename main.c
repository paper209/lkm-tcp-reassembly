#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/net_namespace.h>
#include <linux/ip.h>
#include <linux/udp.h>

#include "config.h"
#include "tcp/tcp.h"

unsigned int parse_protocol(struct iphdr *iph, struct sk_buff *skb) {
    switch (iph->protocol) {
        // tcp
        case 6: {
            parse_tcp(iph, skb);
            break;
        }
    }

    return NF_ACCEPT;
}

unsigned int hook(void *pb, struct sk_buff *skb, const struct nf_hook_state *state) {
    const struct iphdr *iph = ip_hdr(skb);

    unsigned int n = parse_protocol(iph, skb);
    if (n == NF_DROP) return n;

    return NF_ACCEPT;
}

const struct nf_hook_ops nfho = {
    .pf = PF_INET,
    .hook = hook,
    .hooknum = NF_INET_LOCAL_IN,
    .priority = NF_IP_PRI_FIRST,
};

int init(void) {
    if (init_tcp(TCP_MAX_SESSIONS, TCP_MAX_BUFFER, TCP_SESSION_TIMEOUT) == TCP_ALLOC_ERROR) {
        printk(KERN_ERR "init tcp error: alloc error\n");
        return TCP_ALLOC_ERROR;
    }
    
    nf_register_net_hook(&init_net, &nfho);
    printk(KERN_INFO "inbound filter is loaded.\n");

    return 0;
}

void deinit(void) {
    deinit_tcp();
    nf_unregister_net_hook(&init_net, &nfho);
    
    printk(KERN_INFO "inbound filter is unloaded.\n");
}

module_init(init);
module_exit(deinit);

MODULE_LICENSE("GPL");
