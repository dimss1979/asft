#ifndef _ASFT_PROTO_H_
#define _ASFT_PROTO_H_

#include <stdint.h>

#define ASFT_KEY_LEN   32
#define ASFT_NONCE_LEN 8
#define ASFT_TAG_LEN   10

#define ASFT_ECDH_KEY_LEN  32

struct asft_base_hdr {
    uint8_t dst_addr;
    uint8_t nonce[ASFT_NONCE_LEN];
    uint8_t tag[ASFT_TAG_LEN];
} __attribute__((packed));

struct asft_cmd_hdr {
    uint8_t command;
    uint32_t packet_number;
} __attribute__((packed));

struct asft_cmd {
    struct asft_base_hdr base;
    struct asft_cmd_hdr cmd;
} __attribute__((packed));

struct asft_cmd_ecdh {
    struct asft_base_hdr base;
    struct asft_cmd_hdr cmd;
    uint8_t public_key[ASFT_ECDH_KEY_LEN];
} __attribute__((packed));

typedef union _asft_packet {
    struct asft_cmd cmd;
    struct asft_cmd_ecdh ecdh;
} __attribute__((packed)) asft_packet;

enum asft_command {
    ASFT_REQ_ECDH_KEY = 0,
    ASFT_RSP_ECDH_KEY = 128,
};

#endif /* _ASFT_PROTO_H_ */
