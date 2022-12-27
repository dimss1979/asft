#ifndef _ASFT_PROTO_H_
#define _ASFT_PROTO_H_

#include <stdint.h>

#define ASFT_KEY_LEN   32
#define ASFT_NONCE_LEN 12
#define ASFT_TAG_LEN   16

struct asft_base_hdr {
    uint8_t dst_addr;
    uint8_t nonce[ASFT_NONCE_LEN];
    uint8_t tag[ASFT_TAG_LEN];
} __attribute__((packed));

struct asft_cmd_hdr {
    uint8_t command;
    uint32_t dialog_token;
    uint32_t session_token;
} __attribute__((packed));

struct asft_cmd {
    struct asft_base_hdr base;
    struct asft_cmd_hdr cmd;
} __attribute__((packed));

typedef union _asft_packet {
    struct asft_cmd cmd;
} __attribute__((packed)) asft_packet;

#endif /* _ASFT_PROTO_H_ */
