#include "ring.h"
#include "snout.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Nadev");
MODULE_DESCRIPTION("A packet sniffer kernel module");

#define DEVICE_NAME "snout"

int ring_size = 1 << 20;
module_param(ring_size, int, 0);

int snaplen = 65535 - sizeof(struct pcap_packet_hdr) - SIZE_METADATA_BYTE_LEN;
module_param(snaplen, int, 0);

static u8 *snout_stage;
static u8 *snout_rbuf;

static struct ring *snout_ring;

static struct snout_stats snout_stats;
static struct pcap_global_hdr global_hdr;
static struct snout_filter snout_filter = {0};
static struct packet_type snout_pt = {
    .dev = NULL, .type = htons(ETH_P_ALL), .func = snout_dev_add_pack_callback};
static struct class *cls;
static int major;

static struct file_operations snoutdev_fops = {.open = snout_open,
                                               .release = snout_release,
                                               .read = snout_read,
                                               .poll = snout_poll,
                                               .unlocked_ioctl = snout_ioctl,
                                               .owner = THIS_MODULE};

static u32 vlan_tag_restore(struct sk_buff *skb, u32 caplen,
                            struct pcap_packet_hdr *packet_hdr) {
  const u32 off = 2 * ETH_ALEN;
  const u32 tagsz = VLAN_HLEN;

  if (!skb_vlan_tag_present(skb) ||
      eth_hdr(skb)->h_proto == htons(ETH_P_8021Q) || caplen < off + tagsz) {
    return caplen;
  }

  memmove(snout_stage + off + tagsz, snout_stage + off,
          min(caplen, snaplen - tagsz) - off);
  put_unaligned_be16(ETH_P_8021Q, snout_stage + off);
  put_unaligned_be16(skb_vlan_tag_get(skb), snout_stage + off + 2);

  caplen = min(caplen + tagsz, snaplen);
  packet_hdr->captured_length = cpu_to_le32(caplen);
  packet_hdr->original_length = cpu_to_le32(skb->len + tagsz);
  return caplen;
}

int snout_dev_add_pack_callback(struct sk_buff *skb, struct net_device *dev,
                                struct packet_type *pt,
                                struct net_device *orig_dev) {
  spin_lock_bh(&snout_ring->lock);

  struct timespec64 ts;
  ktime_get_real_ts64(&ts);
  struct pcap_packet_hdr packet_hdr;
  u32 caplen = min_t(u32, skb->len, snaplen);

  if (snout_filter.protocol != 0 &&
      eth_hdr(skb)->h_proto != snout_filter.protocol) {
    spin_unlock_bh(&snout_ring->lock);
    return NET_RX_DROP;
  }

  if (skb_copy_bits(skb, 0, snout_stage, caplen) < 0) {
    spin_unlock_bh(&snout_ring->lock);
    return NET_RX_DROP;
  }
  packet_hdr.timestamp_seconds = cpu_to_le32(ts.tv_sec);
  packet_hdr.timestamp_microseconds = cpu_to_le32(ts.tv_nsec / 1000);
  packet_hdr.captured_length = cpu_to_le32(caplen);
  packet_hdr.original_length = cpu_to_le32(skb->len);

  caplen = vlan_tag_restore(skb, caplen, &packet_hdr);

  int ret =
      ring_write_record(snout_ring, &packet_hdr, sizeof(struct pcap_packet_hdr),
                        snout_stage, caplen);
  if (ret == 0) {
    snout_stats.packets++;
    snout_stats.bytes += caplen;
  }
  spin_unlock_bh(&snout_ring->lock);
  if (ret == 0) {
    wake_up_interruptible(&snout_ring->wait);
  }

  return NET_RX_DROP;
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

ssize_t snout_read(struct file *flip, char __user *buffer, size_t length,
                   loff_t *offset) {
  if (length == 0) {
    return 0;
  }

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
  while (length - bytes_read > 0) {
    int bytes_to_read = min_t(size_t, snaplen, length - bytes_read);
    spin_lock_bh(&snout_ring->lock);
    if (ring_available(snout_ring) == 0) {
      spin_unlock_bh(&snout_ring->lock);
      if (bytes_read > 0) {
        break;
      }
      if (flip->f_flags & O_NONBLOCK) {
        return -EAGAIN;
      }
      if (wait_event_interruptible(snout_ring->wait,
                                   ring_available(snout_ring) > 0)) {
        return -ERESTARTSYS;
      }
      continue;
    }
    size_t len = ring_read(snout_ring, snout_rbuf, bytes_to_read);
    spin_unlock_bh(&snout_ring->lock);
    if (copy_to_user(buffer + bytes_read, snout_rbuf, len)) {
      if (bytes_read > 0) {
        return bytes_read;
      }
      return -EFAULT;
    }
    bytes_read += len;
  }
  return bytes_read;
}

__poll_t snout_poll(struct file *flip, struct poll_table_struct *poll_table) {
  struct snout_file_ctx *ctx = flip->private_data;
  __poll_t poll_mask = 0;

  poll_wait(flip, &snout_ring->wait, poll_table);

  if (!ctx->hdr_sent) {
    poll_mask |= POLLIN | POLLRDNORM;
  }

  spin_lock_bh(&snout_ring->lock);
  if (ring_available(snout_ring) > 0) {
    poll_mask |= POLLIN | POLLRDNORM;
  }
  spin_unlock_bh(&snout_ring->lock);

  return poll_mask;
}

long snout_ioctl(struct file *flip, unsigned int cmd, unsigned long arg) {
  switch (cmd) {
  case SNAPIOC_GET_STATS:
    struct snout_stats statscopy;
    spin_lock_bh(&snout_ring->lock);
    statscopy = snout_stats;
    statscopy.overflow_count = snout_ring->overflow_count;
    statscopy.dropped_bytes = snout_ring->dropped_bytes;
    statscopy.ring_usage =
        ring_available(snout_ring) * 100 / (snout_ring->size - 1);
    spin_unlock_bh(&snout_ring->lock);
    if (copy_to_user((void __user *)arg, &statscopy, sizeof(statscopy))) {
      return -EFAULT;
    }
    break;
  case SNAPIOC_RESET_STATS:
    spin_lock_bh(&snout_ring->lock);
    snout_stats.bytes = 0;
    snout_stats.packets = 0;
    snout_ring->overflow_count = 0;
    snout_ring->dropped_bytes = 0;
    snout_stats.ring_usage = 0;
    spin_unlock_bh(&snout_ring->lock);
    break;
  case SNAPIOC_SET_FILTER:
    struct snout_filter filter;
    if (copy_from_user(&filter, (void __user *)arg, sizeof(filter))) {
      return -EFAULT;
    }
    spin_lock_bh(&snout_ring->lock);
    snout_filter = filter;
    spin_unlock_bh(&snout_ring->lock);
    break;
  default:
    return -ENOTTY;
  }
  return 0;
}

static int __init snout_init(void) {
  // params validation
  if (ring_size < 4096) {
    pr_err("snout: ring_size %d too small (min 4096)\n", ring_size);
    return -EINVAL;
  }
  if (snaplen < 0 || snaplen > 65535 - sizeof(struct pcap_packet_hdr) -
                                   SIZE_METADATA_BYTE_LEN) {
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
  global_hdr.link_layer_type = cpu_to_le32(1);

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

  snout_rbuf = kzalloc(snaplen, GFP_KERNEL);
  if (!snout_rbuf) {
    ring_destroy(snout_ring);
    kfree(snout_stage);
    pr_err("snout: read buffer failed allocation\n");
    return -ENOMEM;
  }

  major = register_chrdev(0, DEVICE_NAME, &snoutdev_fops);
  if (major < 0) {
    pr_err("snout: failed to register snout char device. err: %d\n", major);
    ring_destroy(snout_ring);
    kfree(snout_stage);
    kfree(snout_rbuf);
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
    kfree(snout_rbuf);
    unregister_chrdev(major, DEVICE_NAME);
    return PTR_ERR(cls);
  }
  struct device *dev =
      device_create(cls, NULL, MKDEV(major, 0), NULL, DEVICE_NAME);

  if (IS_ERR(dev)) {
    pr_err("snout: failed to create device, err: %ld\n", PTR_ERR(dev));
    ring_destroy(snout_ring);
    kfree(snout_stage);
    kfree(snout_rbuf);
    unregister_chrdev(major, DEVICE_NAME);
    class_destroy(cls);
    return PTR_ERR(dev);
  }

  dev_add_pack(&snout_pt);

  pr_info("snout device init success\n");
  return 0;
}

static void __exit snout_exit(void) {
  dev_remove_pack(&snout_pt);
  device_destroy(cls, MKDEV(major, 0));
  class_destroy(cls);
  unregister_chrdev(major, DEVICE_NAME);

  spin_lock_bh(&snout_ring->lock);

  unsigned int usage =
      ring_available(snout_ring) * 100 / (snout_ring->size - 1);
  pr_info("snout: packets=%llu, bytes=%llu, overflow_count=%llu, "
          "dropped_bytes=%llu, ring_usage=%u%%",
          snout_stats.packets, snout_stats.bytes, snout_ring->overflow_count,
          snout_ring->dropped_bytes, usage);

  spin_unlock_bh(&snout_ring->lock);

  kfree(snout_rbuf);
  kfree(snout_stage);
  ring_destroy(snout_ring);

  pr_info("snout: exit success\n");
  return;
}

module_init(snout_init);
module_exit(snout_exit);
