#ifndef RING
#define RING

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/vmalloc.h>

struct ring {
  u64 *dropped;
  u8 *buf;
  size_t size;
  unsigned long head;
  unsigned long tail;
  spinlock_t lock;
};

static struct ring *ring_init(size_t size);
static void ring_destroy(struct ring *ring);
static size_t ring_space(struct ring *ring);
static size_t ring_available(struct ring *ring);
static size_t ring_put(struct ring *ring, const u8 *data, size_t len);
// static char ring_write_record(struct ring *ring);
// static char ring_read(struct ring *ring);
// static char ring_reset(struct ring *ring);
#endif
