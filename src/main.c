#include "ring.h"
#include "snout.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Nadev");
MODULE_DESCRIPTION("A packet sniffer kernel module");

#define DEVICE_NAME "snout"

int ring_size = 1 << 20;
module_param(ring_size, int, 0);

int snaplen = 65535;
module_param(snaplen, int, 0);

static u8 *snout_stage;

static struct ring *snout_ring;

static u64 snout_packets = 0, snout_bytes = 0;
static struct pcap_global_hdr global_hdr;

static struct class *cls;
static struct nf_hook_ops nfho;
static int major;

static struct file_operations snoutdev_fops = {.open = snout_open,
                                               .release = snout_release,
                                               .read = snout_read,
                                               .poll = snout_poll,
                                               .owner = THIS_MODULE};

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
  spin_unlock_bh(&snout_ring->lock);
  if (ret == 0) {
    wake_up_interruptible(&snout_ring->wait);
    snout_packets++;
    snout_bytes += caplen;
  }

  return NF_ACCEPT;
}

int snout_open(struct inode *inode, struct file *flip) {
  struct snout_file_ctx *ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
  if (!ctx)
    return -ENOMEM;
  flip->private_data = ctx;

  return 0;
}

int snout_release(struct inode *inode, struct file *flip) {
  kfree(flip->private_data);

  return 0;
}

static int __init snout_init(void) {
  int err;

  // params validation
  if (ring_size < 4096) {
    pr_err("snout: ring_size %d too small (min 4096)\n", ring_size);
    return -EINVAL;
  }
  if (snaplen < 0 || snaplen > 65535) {
    pr_err("snout: snaplen %d out of range\n", snaplen);
    return -EINVAL;
  }
  if (snaplen > ring_size - (int)sizeof(struct pcap_packet_hdr) - 1) {
    pr_err("snout: snaplen %d exceeds ring capacity\n", snaplen);
    return -EINVAL;
  }

  global_hdr.magic_number = cpu_to_le32(0xa1b2c3d4);
  global_hdr.version_major = cpu_to_le16(2);
  global_hdr.version_minor = cpu_to_le16(4);
  global_hdr.time_zone_correction = cpu_to_le32(0);
  global_hdr.timestamp_accuracy = cpu_to_le32(0);
  global_hdr.snapshot_length = cpu_to_le32(snaplen);
  global_hdr.link_layer_type = cpu_to_le32(101);

  snout_ring = ring_init(ring_size);
  if (!snout_ring) {
    pr_err("snout: ring failed allocation\n");
    return -ENOMEM;
  }

  snout_stage = kzalloc(snaplen, GFP_KERNEL);
  if (!snout_stage) {
    ring_destroy(snout_ring);
    pr_err("snout: stage buffer failed allocation\n");
    return -ENOMEM;
  }

  major = register_chrdev(0, DEVICE_NAME, &snoutdev_fops);
  if (major < 0) {
    pr_err("snout: failed to register snout char device. err: %d\n", major);
    ring_destroy(snout_ring);
    kfree(snout_stage);
    return major;
  }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
  cls = class_create(DEVICE_NAME);
#else
  cls = class_create(THIS_MODULE, DEVICE_NAME);
#endif
  if (IS_ERR(cls)) {
    pr_err("snout: failed to create class, err: %ld\n", PTR_ERR(cls));
    ring_destroy(snout_ring);
    kfree(snout_stage);
    unregister_chrdev(major, DEVICE_NAME);
    return PTR_ERR(cls);
  }
  struct device *dev =
      device_create(cls, NULL, MKDEV(major, 0), NULL, DEVICE_NAME);

  if (IS_ERR(dev)) {
    pr_err("snout: failed to create device, err: %ld\n", PTR_ERR(dev));
    ring_destroy(snout_ring);
    kfree(snout_stage);
    unregister_chrdev(major, DEVICE_NAME);
    class_destroy(cls);
    return PTR_ERR(dev);
  }

  nfho.hook = netfilter_hook;
  nfho.hooknum = NF_INET_PRE_ROUTING;
  nfho.pf = PF_INET;
  nfho.priority = NF_IP_PRI_FIRST;

  err = nf_register_net_hook(&init_net, &nfho);
  if (err < 0) {
    pr_err("snout: nf_register_net_hook failed: %d\n", err);
    ring_destroy(snout_ring);
    kfree(snout_stage);
    unregister_chrdev(major, DEVICE_NAME);
    class_destroy(cls);
    device_destroy(dev->class, dev->devt);
    return err;
  }

  pr_info("snout device init success\n");
  return 0;
}

ssize_t snout_read(struct file *flip, char __user *buffer, size_t length,
                   loff_t *offset) {
  int err;
  ssize_t bytes_read = 0;
  struct snout_file_ctx *ctx = flip->private_data;
  if (!ctx->hdr_sent) {
    if (length < sizeof(global_hdr)) {
      return -EINVAL;
    }
    if (copy_to_user(buffer, &global_hdr, sizeof(global_hdr))) {
      return -EFAULT;
    }
    ctx->hdr_sent = true;
    bytes_read += sizeof(global_hdr);
  }

  return bytes_read;
}

__poll_t snout_poll(struct file *flip, struct poll_table_struct *poll_table) {

  return 0;
}

static void __exit snout_exit(void) {
  nf_unregister_net_hook(&init_net, &nfho);
  device_destroy(cls, MKDEV(major, 0));
  class_destroy(cls);
  unregister_chrdev(major, DEVICE_NAME);

  spin_lock_bh(&snout_ring->lock);

  unsigned int usage =
      ring_available(snout_ring) * 100 / (snout_ring->size - 1);
  pr_info("snout: packets=%llu, bytes=%llu, dropped=%llu, ring_usage=%u%%",
          snout_packets, snout_bytes, snout_ring->dropped, usage);

  spin_unlock_bh(&snout_ring->lock);

  ring_destroy(snout_ring);
  kfree(snout_stage);

  pr_info("snout: exit success\n");
  return;
}

module_init(snout_init);
module_exit(snout_exit);
