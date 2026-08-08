#ifndef RING
#define RING

#include "snout.h"
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/minmax.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/types.h>

struct ring {
  u8 *buf;
  u64 dropped;
  size_t size;
  unsigned long head;
  unsigned long tail;
  spinlock_t lock;
};

struct ring *ring_init(size_t size);
void ring_destroy(struct ring *ring);
static size_t ring_space(struct ring *ring);
static size_t ring_available(struct ring *ring);
static size_t ring_put(struct ring *ring, const u8 *data, size_t len);
int ring_write_record(struct ring *ring, const void *hdr, size_t hdr_len,
                      const void *payload, size_t payload_len);
//  char ring_read(struct ring *ring);
//  char ring_reset(struct ring *ring);
#endif
