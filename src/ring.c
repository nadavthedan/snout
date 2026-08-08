#include "ring.h"
#include "asm-generic/bug.h"
#include "linux/spinlock.h"
#include <linux/string.h>
#include <stddef.h>

static struct ring *ring_init(size_t size) {
  struct ring *ring = vcalloc(1, sizeof(*ring));
  if (!ring) {
    return NULL;
  }
  ring->buf = vmalloc(size);
  if (!ring->buf) {
    vfree(ring);
    return NULL;
  }
  ring->size = size;
  spin_lock_init(&ring->lock);
  return ring;
};

static void ring_destroy(struct ring *ring) {
  vfree(ring->buf);
  vfree(ring);
};

static size_t ring_space(struct ring *ring) {
  return ring->size - (ring->head - ring->tail) - 1;
};
static size_t ring_available(struct ring *ring) {
  size_t available = ring->head - ring->tail;
  return available < ring->size ? available : ring->size - 1;
};

static size_t ring_put(struct ring *ring, const u8 *data, size_t len) {
  size_t pos, first;

  if (WARN_ON_ONCE(len > ring_space(ring))) {
    return 0;
  };

  pos = ring->head % ring->size;
  first = min(len, ring->size - pos);

  memcpy(ring->buf + pos, data, first);
  memcpy(ring->buf, data + first, len - first);
  ring->head += len;

  return len;
}

// static char ring_write_record(struct ring *ring) {};
// static char ring_read(struct ring *ring) {};
// static char ring_reset(struct ring *ring) {};
