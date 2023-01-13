#ifndef _ASFT_CRYPTO_H_
#define _ASFT_CRYPTO_H_

#include "asft_proto.h"

size_t asft_crypto_init();

int asft_packet_encrypt(
    asft_packet **cpkt_ptr,
    void *pkt,
    size_t pkt_len,
    unsigned char *key
);

int asft_packet_decrypt(
    asft_packet **pkt_ptr,
    asft_packet *cpkt,
    size_t cpkt_len,
    unsigned char *key
);

#endif
