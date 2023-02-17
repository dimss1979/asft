#ifndef _ASFT_PROTO_H_
#define _ASFT_PROTO_H_

#include <stdint.h>

#define ASFT_TAG_LEN   10

#define ASFT_ECDH_KEY_LEN  32

struct asft_base_hdr {
    union {
        uint32_t packet_number;
        unsigned char pn[4];
    };
    uint8_t tag[ASFT_TAG_LEN];
    uint8_t command;
} __attribute__((packed));

struct asft_cmd_ecdh {
    struct asft_base_hdr base;
    uint8_t public_key[ASFT_ECDH_KEY_LEN];
} __attribute__((packed));

typedef union _asft_packet {
    struct asft_base_hdr base;
    struct asft_cmd_ecdh ecdh;
} __attribute__((packed)) asft_packet;

enum asft_command {
    ASFT_REQ_ECDH_KEY = 0,
    ASFT_RSP_ECDH_KEY = 128,
};

#endif /* _ASFT_PROTO_H_ */
