#include <linux/printk.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Nadev");
MODULE_DESCRIPTION("A packet sniffer kernel module");

static struct nf_hook_ops nfho;

static unsigned int netfilter_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    static unsigned long packet_count = 0;

    if ((++packet_count % 1000) == 0) {
        pr_info("Logged %lu packets!\n", packet_count);
    }
    return NF_ACCEPT;
}

static int __init snout_init(void) {
  nfho.hook = netfilter_hook;
  nfho.hooknum = NF_INET_PRE_ROUTING;
  nfho.pf = PF_INET;
  nfho.priority = NF_IP_PRI_FIRST;

  nf_register_net_hook(&init_net, &nfho);

  pr_info("snount init success\n");
  return 0;
}

static void __exit snout_exit(void) {
  nf_unregister_net_hook(&init_net, &nfho);

  pr_info("snount exit success\n");
  return;
}

module_init(snout_init);
module_exit(snout_exit);
