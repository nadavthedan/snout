#include "ring.h"
#include "snout.h"
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/printk.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/tcp.h>
#include <linux/timekeeping.h>
#include <linux/udp.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Nadev");
MODULE_DESCRIPTION("A packet sniffer kernel module");

int ring_size = 1 << 20;
module_param(ring_size, int, 0);

int snaplen = 65535;
module_param(snaplen, int, 0);

static u8 *snout_stage;

static struct ring *snout_ring;

static u64 snout_packets = 0, snout_bytes = 0;

static struct nf_hook_ops nfho;

static unsigned int netfilter_hook(void *priv, struct sk_buff *skb,
                                   const struct nf_hook_state *state) {
  spin_lock_bh(&snout_ring->lock);

  struct timespec64 ts;
  ktime_get_real_ts64(&ts);
  struct pcap_packet_hdr packet_hdr;
  u32 caplen = min_t(u32, skb->len, snaplen);

  packet_hdr.timestamp_seconds = cpu_to_le32(ts.tv_sec);
  packet_hdr.timestamp_microseconds = cpu_to_le32(ts.tv_nsec / 1000);
  packet_hdr.captured_length = cpu_to_le32(caplen);
  packet_hdr.original_length = cpu_to_le32(skb->len);

  if (skb_copy_bits(skb, 0, snout_stage, caplen) < 0) {
    spin_unlock_bh(&snout_ring->lock);
    return NF_ACCEPT; // Skip packet
  }

  int ret =
      ring_write_record(snout_ring, &packet_hdr, sizeof(struct pcap_packet_hdr),
                        snout_stage, caplen);
  if (ret == 0) {
    snout_packets++;
    snout_bytes += caplen;
  }

  spin_unlock_bh(&snout_ring->lock);
  return NF_ACCEPT;
}

static int __init snout_init(void) {
  int err;

  // params validation
  if (ring_size < 4096) {
    pr_err("snount: ring_size %d too small (min 4096)\n", ring_size);
    return -EINVAL;
  }
  if (snaplen < 0 || snaplen > 65535) {
    pr_err("snount: snaplen %d out of range\n", snaplen);
    return -EINVAL;
  }
  if (snaplen > ring_size - (int)sizeof(struct pcap_packet_hdr) - 1) {
    pr_err("snount: snaplen %d exceeds ring capacity\n", snaplen);
    return -EINVAL;
  }

  snout_ring = ring_init(ring_size);
  if (!snout_ring) {
    pr_err("snount: ring failed allocation\n");
    return -ENOMEM;
  }

  snout_stage = kzalloc(snaplen, GFP_KERNEL);
  if (!snout_stage) {
    ring_destroy(snout_ring);
    pr_err("snount: stage buffer failed allocation\n");
    return -ENOMEM;
  }

  nfho.hook = netfilter_hook;
  nfho.hooknum = NF_INET_PRE_ROUTING;
  nfho.pf = PF_INET;
  nfho.priority = NF_IP_PRI_FIRST;

  err = nf_register_net_hook(&init_net, &nfho);
  if (err < 0) {
    pr_err("snount: nf_register_net_hook failed: %d\n", err);
    ring_destroy(snout_ring);
    kfree(snout_stage);
    return err;
  }

  pr_info("snount init success\n");
  return 0;
}

static void __exit snout_exit(void) {
  nf_unregister_net_hook(&init_net, &nfho);

  spin_lock_bh(&snout_ring->lock);

  unsigned int usage =
      ring_available(snout_ring) * 100 / (snout_ring->size - 1);
  pr_info("packets=%llu, bytes=%llu, dropped=%llu, ring_usage=%u%%",
          snout_packets, snout_bytes, snout_ring->dropped, usage);

  spin_unlock_bh(&snout_ring->lock);

  ring_destroy(snout_ring);
  kfree(snout_stage);

  pr_info("snount exit success\n");
  return;
}

module_init(snout_init);
module_exit(snout_exit);
