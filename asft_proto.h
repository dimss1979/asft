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
    uint8_t ack;
} __attribute__((packed));

struct asft_pkt_nodata {
    struct asft_pkt_base b;
    uint8_t cmd;
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
