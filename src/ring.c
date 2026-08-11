#include "ring.h"

struct ring *ring_init(size_t size) {
  struct ring *ring = kzalloc(sizeof(*ring), GFP_KERNEL);
  if (!ring) {
    return NULL;
  }
  ring->buf = kvzalloc(size, GFP_KERNEL);
  if (!ring->buf) {
    kfree(ring);
    return NULL;
  }
  ring->size = size;
  spin_lock_init(&ring->lock);
  return ring;
};

void ring_destroy(struct ring *ring) {
  kvfree(ring->buf);
  kfree(ring);
};

static size_t ring_space(struct ring *ring) {
  return ring->size - (ring->head - ring->tail) - 1;
};
size_t ring_available(struct ring *ring) {
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

int ring_write_record(struct ring *ring, const void *hdr, size_t hdr_len,
                      const void *payload, size_t payload_len) {
  size_t total = hdr_len + payload_len;
  if (total > ring_space(ring)) {
    ring->dropped++;
    return -ENOSPC;
  }
  ring_put(ring, hdr, hdr_len);
  ring_put(ring, payload, payload_len);
  return 0;
};

size_t ring_read(struct ring *ring, u8 *buf, size_t len) {
  size_t available, read_size, first, pos;
  available = ring_available(ring);
  if (!available) {
    return 0;
  }
  read_size = min(len, available);
  pos = ring->tail % ring->size;
  first = min(read_size, ring->size - pos);
  memcpy(buf, ring->buf + pos, first);
  memcpy(buf + first, ring->buf, read_size - first);
  ring->tail += read_size;
  return read_size;
};

void ring_reset(struct ring *ring) {
  ring->head = 0;
  ring->tail = 0;
  ring->dropped = 0;
};
