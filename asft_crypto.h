#ifndef _ASFT_CRYPTO_H_
#define _ASFT_CRYPTO_H_

#include "asft_proto.h"

struct asft_crypto_ctx;

struct asft_crypto_ctx *asft_crypto_ctx_init(char *password);

void asft_crypto_set_session_timestamp(struct asft_crypto_ctx *ctx);

int asft_encrypt_req(
    struct asft_crypto_ctx *ctx,
    asft_pkt *cpkt,
    asft_pkt *pkt,
    size_t pkt_len
);

int asft_decrypt_req(
    struct asft_crypto_ctx *ctx,
    asft_pkt *pkt,
    asft_pkt *cpkt,
    size_t cpkt_len
);

int asft_encrypt_resp(
    struct asft_crypto_ctx *ctx,
    asft_pkt *cpkt,
    asft_pkt *pkt,
    size_t pkt_len
);

int asft_decrypt_resp(
    struct asft_crypto_ctx *ctx,
    asft_pkt *pkt,
    asft_pkt *cpkt,
    size_t cpkt_len
);

int asft_sign_msg(
    struct asft_crypto_ctx *ctx,
    void *mac,
    size_t mac_len,
    void *msg,
    size_t msg_len
);

int asft_verify_msg(
    struct asft_crypto_ctx *ctx,
    void *mac,
    size_t mac_len,
    void *msg,
    size_t msg_len
);

int asft_sign_msg_hdr(
    struct asft_crypto_ctx *ctx,
    void *mac,
    size_t mac_len,
    void *msg_hdr,
    size_t msg_hdr_len
);

int asft_verify_msg_hdr(
    struct asft_crypto_ctx *ctx,
    void *mac,
    size_t mac_len,
    void *msg_hdr,
    size_t msg_hdr_len
);

#endif
