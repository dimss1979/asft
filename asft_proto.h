#ifndef _ASFT_PROTO_H_
#define _ASFT_PROTO_H_

#include <stdint.h>

#define ASFT_TAG_LEN   10
#define ASFT_BLOCK_LEN  100

#define ASFT_PKT_LEN_NODATA  (sizeof(struct asft_pkt_nodata))
#define ASFT_PKT_LEN_DATA    (sizeof(struct asft_pkt_data))

struct asft_pkt_base {
    uint8_t tag[ASFT_TAG_LEN];
    uint32_t nonce;
    uint8_t ack;
} __attribute__((packed));

struct asft_pkt_nodata {
    struct asft_pkt_base b;
} __attribute__((packed));

struct asft_pkt_data {
    struct asft_pkt_base b;
    uint16_t block_idx;
    uint8_t data[ASFT_BLOCK_LEN];
} __attribute__((packed));

typedef union {
    struct asft_pkt_base b;
    struct asft_pkt_nodata nodata;
    struct asft_pkt_data data;
} __attribute__((packed)) asft_pkt;

#endif /* _ASFT_PROTO_H_ */
