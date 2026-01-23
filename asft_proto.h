#ifndef _ASFT_PROTO_H_
#define _ASFT_PROTO_H_

#include <stdint.h>

#define ASFT_TAG_LEN    4
#define ASFT_TS_LEN     sizeof(uint64_t)
#define ASFT_TS_XMIT    2
#define ASFT_TS_HIDE    (ASFT_TS_LEN - ASFT_TS_XMIT)
#define ASFT_BLOCK_LEN  100

#define ASFT_PKT_LEN_NODATA  (sizeof(struct asft_pkt_nodata))
#define ASFT_PKT_LEN_DATA    (sizeof(struct asft_pkt_data))

#define ASFT_FLAGS_CMD_SHIFT 4
#define ASFT_FLAGS_SEQ_SHIFT 1

enum asft_cmd {
    ASFT_CMD_RESET = 0,
    ASFT_CMD_READY = 1,
    ASFT_CMD_NOT_READY = 2,
    ASFT_CMD_DATA = 3,
    ASFT_CMD_NODATA = 4,
};

struct asft_pkt_base {
    uint8_t tag[ASFT_TAG_LEN];
    uint8_t timestamp[ASFT_TS_XMIT];
    uint8_t flags;
} __attribute__((packed));

struct asft_pkt_nodata {
    struct asft_pkt_base b;
} __attribute__((packed));

struct asft_pkt_data {
    struct asft_pkt_base b;
    uint8_t data[ASFT_BLOCK_LEN];
} __attribute__((packed));

typedef union {
    struct asft_pkt_base b;
    struct asft_pkt_nodata nodata;
    struct asft_pkt_data data;
} __attribute__((packed)) asft_pkt;

struct asft_pkt_flags {
    uint8_t cmd;
    uint8_t seq;
    uint8_t ack;
};

static inline void asft_pkt_flags_decode(struct asft_pkt_flags *o, uint8_t i)
{
    o->cmd = i >> ASFT_FLAGS_CMD_SHIFT;
    o->seq = (i >> ASFT_FLAGS_SEQ_SHIFT) & 1;
    o->ack = i & 1;
}

static inline uint8_t asft_pkt_flags_encode(struct asft_pkt_flags *i)
{
    uint8_t o = i->cmd << ASFT_FLAGS_CMD_SHIFT;
    o |= (i->seq & 1) << ASFT_FLAGS_SEQ_SHIFT;
    o |= i->ack & 1;

    return o;
}

#endif /* _ASFT_PROTO_H_ */
