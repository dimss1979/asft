#ifndef _ASFT_PROTO_H_
#define _ASFT_PROTO_H_

#include <stdint.h>

#define ASFT_TAG_LEN    4
#define ASFT_TS_LEN     sizeof(uint64_t)
#define ASFT_TS_XMIT    2
#define ASFT_TS_HIDE    (ASFT_TS_LEN - ASFT_TS_XMIT)
#define ASFT_BLOCK_LEN  100

typedef struct _asft_pkt {
    uint8_t tag[ASFT_TAG_LEN];
    uint8_t timestamp[ASFT_TS_XMIT];
    uint8_t flags;
    uint8_t data[ASFT_BLOCK_LEN];
} __attribute__((packed)) asft_pkt;

struct asft_pkt_flags {
    uint8_t rst;
    uint8_t seq;
    uint8_t ack;
};

static inline void asft_pkt_flags_decode(struct asft_pkt_flags *o, uint8_t i)
{
    o->rst = (i >> 2) & 1;
    o->seq = (i >> 1) & 1;
    o->ack = (i >> 0) & 1;
}

static inline uint8_t asft_pkt_flags_encode(struct asft_pkt_flags *i)
{
    return
        ((i->rst & 1) << 2) |
        ((i->seq & 1) << 1) |
        ((i->ack & 1) << 0);
}

#endif /* _ASFT_PROTO_H_ */
