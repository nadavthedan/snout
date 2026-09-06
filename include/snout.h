#ifndef SNOUT
#define SNOUT
#include "ring.h"
#include <linux/byteorder/little_endian.h>
#include <linux/device.h>
#include <linux/errno.h>
#include <linux/etherdevice.h>
#include <linux/fcntl.h>
#include <linux/fs.h>
#include <linux/if_vlan.h>
#include <linux/init.h>
#include <linux/ioctl.h>
#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/poll.h>
#include <linux/printk.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/tcp.h>
#include <linux/timekeeping.h>
#include <linux/types.h>
#include <linux/udp.h>
#include <linux/version.h>

struct pcap_global_hdr {
  __le32 magic_number;
  __le16 version_major;
  __le16 version_minor;
  __le32 time_zone_correction;
  __le32 timestamp_accuracy;
  __le32 snapshot_length;
  __le32 link_layer_type;
} __packed;

struct pcap_packet_hdr {
  __le32 timestamp_seconds;
  __le32 timestamp_microseconds;
  __le32 captured_length;
  __le32 original_length;
} __packed;

struct snout_file_ctx {
  bool hdr_sent;
};

struct snout_filter {
  __be16 protocol;
};

int snout_open(struct inode *, struct file *);
int snout_release(struct inode *, struct file *);
ssize_t snout_read(struct file *flip, char __user *buffer, size_t length,
                   loff_t *offset);
__poll_t snout_poll(struct file *flip, struct poll_table_struct *poll_table);
long snout_ioctl(struct file *flip, unsigned int cmd, unsigned long arg);

int snout_dev_add_pack_callback(struct sk_buff *skb, struct net_device *dev,
                                struct packet_type *pt,
                                struct net_device *orig_dev);

// start ioctl snout commands
#define SNAPIOC_MAGIC 'S'
struct snout_stats {
  __u64 packets, bytes, overflow_count, dropped_bytes;
  __u32 ring_usage, policy;
};
#define SNAPIOC_GET_STATS _IOR(SNAPIOC_MAGIC, 1, struct snout_stats)
#define SNAPIOC_RESET_STATS _IO(SNAPIOC_MAGIC, 2)
#define SNAPIOC_SET_FILTER _IOW(SNAPIOC_MAGIC, 3, struct snout_filter)
#define SNAPIOC_SET_DROP_POLICY _IOW(SNAPIOC_MAGIC, 4, __u32)
// end ioctl snout commands
#endif
