#ifndef _ASFT_PROTO_H_
#define _ASFT_PROTO_H_

#include <stdint.h>

#define ASFT_TS_TOLERANCE 3600
#define ASFT_MAX_RETRIES 10

#define ASFT_KEY_LEN   32
#define ASFT_TAG_LEN   10
#define ASFT_ECDH_KEY_LEN  32
#define ASFT_BLOCK_LEN  100

#define ASFT_PKT_LEN_ECDH    (sizeof(struct asft_pkt_ecdh))
#define ASFT_PKT_LEN_NODATA  (sizeof(struct asft_pkt_nodata))
#define ASFT_PKT_LEN_DATA    (sizeof(struct asft_pkt_data))

struct asft_pkt_ecdh {
    uint8_t tag[ASFT_TAG_LEN];
    uint32_t timestamp;
    uint8_t public_key[ASFT_ECDH_KEY_LEN];
} __attribute__((packed));


struct asft_pkt_nodata {
    uint8_t tag[ASFT_TAG_LEN];
    uint16_t packet_number;
    uint8_t ack;
} __attribute__((packed));

struct asft_pkt_data {
    uint8_t tag[ASFT_TAG_LEN];
    uint16_t packet_number;
    uint8_t ack;
    uint16_t block_idx;
    uint8_t data[ASFT_BLOCK_LEN];
} __attribute__((packed));

_Static_assert(ASFT_PKT_LEN_ECDH != ASFT_PKT_LEN_DATA);

typedef union {
    struct asft_pkt_ecdh ecdh;
    struct asft_pkt_nodata nodata;
    struct asft_pkt_data data;
} __attribute__((packed)) asft_pkt;

#endif /* _ASFT_PROTO_H_ */
