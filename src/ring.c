#include "ring.h"
#include <stdint.h>

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
  ring->policy = DROP_NEWEST;
  ring->size = size;
  spin_lock_init(&ring->lock);
  init_waitqueue_head(&ring->wait);
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

static int handle_drop_policy(struct ring *ring, size_t total) {
  u16 first_packet_length;
  switch (ring->policy) {
  case DROP_NEWEST:
    ring->overflow_count++;
    ring->dropped_bytes += total;
    return -ENOSPC; // just return no space and skip
  case DROP_OLDEST:
    do {
      ring->overflow_count++;
      first_packet_length = ring->buf[ring->tail];
      ring->tail += first_packet_length;
      ring->dropped_bytes += first_packet_length;
    } while (total < ring_space(ring));
    return 0;
  }
}

int ring_write_record(struct ring *ring, const void *hdr, size_t hdr_len,
                      const void *payload, size_t payload_len) {
  int err;
  size_t total = hdr_len + payload_len + SIZE_METADATA_BYTE_LEN;
  if (total > ring_space(ring)) {
    if ((err = handle_drop_policy(ring, total)) < 0) {
      return err;
    }
  }
  ring_put(ring, (void *)(u16)total, SIZE_METADATA_BYTE_LEN);
  ring_put(ring, hdr, hdr_len);
  ring_put(ring, payload, payload_len);
  return 0;
};

u16 ring_peek_record_len(struct ring *ring) {
  //
  return 0;
}

size_t ring_read(struct ring *ring, u8 *buf, size_t len) {
  size_t available, read_size, first, pos;
  available = ring_available(ring);
  if (!available) {
    return 0;
  }
  read_size = min(len, available);
  pos = ring->tail % ring->size + SIZE_METADATA_BYTE_LEN;
  first = min(read_size, ring->size - pos);
  memcpy(buf, ring->buf + pos, first);
  memcpy(buf + first, ring->buf, read_size - first);
  ring->tail += read_size + SIZE_METADATA_BYTE_LEN;
  return read_size;
};

void ring_reset(struct ring *ring) {
  ring->head = 0;
  ring->tail = 0;
  ring->overflow_count = 0;
};
