#ifndef SNOUT
#define SNOUT
#include "linux/types.h"

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
#endif
