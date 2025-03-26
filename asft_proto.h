#ifndef _ASFT_PROTO_H_
#define _ASFT_PROTO_H_

#include <stdint.h>

#define ASFT_TAG_LEN   10
#define ASFT_ECDH_KEY_LEN  32
#define ASFT_BLOCK_LEN  100

struct asft_base_hdr {
    uint8_t tag[ASFT_TAG_LEN];
    union {
        uint32_t packet_number;
        uint8_t pn[4];
    };
    uint8_t command;
} __attribute__((packed));

struct asft_cmd_ecdh {
    struct asft_base_hdr base;
    uint8_t public_key[ASFT_ECDH_KEY_LEN];
} __attribute__((packed));


struct asft_cmd_nodata {
    struct asft_base_hdr base;
    uint8_t ack;
} __attribute__((packed));

struct asft_cmd_data {
    struct asft_base_hdr base;
    uint8_t ack;
    uint16_t block_idx;
    uint8_t data[ASFT_BLOCK_LEN];
} __attribute__((packed));

typedef union {
    struct asft_base_hdr base;
    struct asft_cmd_ecdh ecdh;
    struct asft_cmd_nodata nodata;
    struct asft_cmd_data data;
} __attribute__((packed)) asft_packet;

enum asft_command {
    ASFT_REQ_ECDH_KEY = 0,
    ASFT_REQ_NODATA,
    ASFT_REQ_DATA,
    ASFT_RSP_ECDH_KEY = 128,
    ASFT_RSP_NODATA,
    ASFT_RSP_DATA,
};

#endif /* _ASFT_PROTO_H_ */
