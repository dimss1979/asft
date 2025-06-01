#ifndef _ASFT_CRYPTO_H_
#define _ASFT_CRYPTO_H_

#include "asft_proto.h"

extern char *asft_crypto_init_key_req;
extern char *asft_crypto_init_key_resp;

struct asft_ecdh;

struct asft_crypto_ctx;

struct asft_crypto_ctx *asft_crypto_ctx_init(char *peer_label);

int asft_set_key(
    char *filename,
    char *keymat,
    size_t keymat_len
);

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

#endif
