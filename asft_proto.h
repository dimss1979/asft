#ifndef _ASFT_PROTO_H_
#define _ASFT_PROTO_H_

#include <stdint.h>

#define ASFT_TAG_LEN   10
#define ASFT_ECDH_KEY_LEN  32
#define ASFT_FILE_NAME_LEN  100
#define ASFT_BLOCK_LEN  100

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

struct asft_cmd_get_file_ack {
    struct asft_base_hdr base;
    uint32_t size;
    uint8_t name[ASFT_FILE_NAME_LEN];
} __attribute__((packed));

struct asft_cmd_get_block_req {
    struct asft_base_hdr base;
    uint32_t block;
} __attribute__((packed));

struct asft_cmd_get_block_rsp {
    struct asft_base_hdr base;
    uint8_t data[ASFT_BLOCK_LEN];
} __attribute__((packed));

typedef union _asft_packet {
    struct asft_base_hdr base;
    struct asft_cmd_ecdh ecdh;
    struct asft_cmd_get_file_ack get_file_ack;
    struct asft_cmd_get_block_req get_block_req;
    struct asft_cmd_get_block_rsp get_block_rsp;
} __attribute__((packed)) asft_packet;

enum asft_command {
    ASFT_REQ_ECDH_KEY = 0,
    ASFT_REQ_GET_FILE,
    ASFT_REQ_GET_BLOCK,
    ASFT_REQ_UPLOAD_COMPLETE,
    ASFT_RSP_ECDH_KEY = 128,
    ASFT_RSP_GET_FILE_ACK,
    ASFT_RSP_GET_FILE_NAK,
    ASFT_RSP_GET_BLOCK,
    ASFT_RSP_UPLOAD_COMPLETE,
    ASFT_RSP_ERROR = 255
};

#endif /* _ASFT_PROTO_H_ */
