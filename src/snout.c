#include "asm-generic/int-ll64.h"
#include "linux/compiler_attributes.h"
#include "linux/spinlock_types.h"
#include "ring.h"
#include <linux/init.h>
#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/printk.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/udp.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Nadev");
MODULE_DESCRIPTION("A packet sniffer kernel module");

int ring_size = 65535;
module_param(ring_size, int, 0);

static struct nf_hook_ops nfho;

static void capture_packet(struct sk_buff *skb) {}

static bool get_packet_payload(struct sk_buff *skb, void *dest_buffer,
                               int max_len, int *bytes_copied) {
  struct iphdr *iph;
  struct iphdr _iph;
  int transport_offset = 0;
  int payload_offset = 0;
  int total_len = skb->len;

  int net_offset = skb_network_offset(skb);
  iph = skb_header_pointer(skb, net_offset, sizeof(struct iphdr), &_iph);
  if (!iph) {
    return false;
  }

  transport_offset = net_offset + (iph->ihl * 4);

  if (iph->protocol == IPPROTO_TCP) {
    struct tcphdr _tcph;
    struct tcphdr *tcph;

    tcph = skb_header_pointer(skb, transport_offset, sizeof(struct tcphdr),
                              &_tcph);
    if (!tcph) {
      return false;
    }

    payload_offset = transport_offset + (tcph->doff * 4);
  } else if (iph->protocol == IPPROTO_UDP) {
    payload_offset = transport_offset + sizeof(struct udphdr);
  } else {
    return false;
  }

  if (payload_offset >= total_len) {
    return false;
  }

  int available_payload_len = total_len - payload_offset;
  int bytes_to_read =
      (available_payload_len < max_len) ? available_payload_len : max_len;

  if (skb_copy_bits(skb, payload_offset, dest_buffer, bytes_to_read) < 0) {
    return false;
  }

  *bytes_copied = bytes_to_read;
  return true;
}

static unsigned int netfilter_hook(void *priv, struct sk_buff *skb,
                                   const struct nf_hook_state *state) {

  char payload_buf[64];
  int bytes_copied = 0;
  if (get_packet_payload(skb, payload_buf, sizeof(payload_buf),
                         &bytes_copied)) {
    pr_info("Successfully grabbed %d bytes of payload!\n", bytes_copied);
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
