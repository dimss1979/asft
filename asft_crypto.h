#ifndef _ASFT_CRYPTO_H_
#define _ASFT_CRYPTO_H_

#include "asft_proto.h"

#define ASFT_KEY_LEN   32

struct asft_ecdh;

struct asft_key {
    unsigned char outer[ASFT_KEY_LEN];
    unsigned char inner[ASFT_KEY_LEN];
};

size_t asft_crypto_init(void);
int asft_crypto_set_network_name(char *new_network_name);

int asft_ecdh_prepare(
    struct asft_ecdh **ecdh,
    unsigned char *pkey_out
);

int asft_ecdh_process(
    struct asft_ecdh **ecdh,
    unsigned char *peer_pkey_in,
    struct asft_key *skey_out
);

int asft_packet_encrypt(
    asft_packet **cpkt_ptr,
    void *pkt,
    size_t pkt_len,
    struct asft_key *key
);

int asft_packet_decrypt(
    asft_packet **pkt_ptr,
    asft_packet *cpkt,
    size_t cpkt_len,
    struct asft_key *key
);

int asft_kdf(
    struct asft_key *key,
    char *password
);

#endif
