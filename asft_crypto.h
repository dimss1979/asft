#ifndef _ASFT_CRYPTO_H_
#define _ASFT_CRYPTO_H_

#include "asft_proto.h"

extern char *asft_crypto_init_key_req;
extern char *asft_crypto_init_key_resp;

struct asft_ecdh;

struct asft_key {
    unsigned char enc[ASFT_KEY_LEN];
    unsigned char auth[ASFT_KEY_LEN];
    unsigned char auth_blob[ASFT_KEY_LEN];
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
    struct asft_key *skey_req,
    struct asft_key *skey_resp
);

int asft_pkt_encrypt(
    void *cpkt,
    void *pkt,
    size_t pkt_len,
    struct asft_key *key
);

int asft_pkt_decrypt(
    void *pkt,
    void *cpkt,
    size_t cpkt_len,
    struct asft_key *key
);

int asft_kdf_once(
    unsigned char *key,
    void *keymat,
    size_t keymat_len,
    void *info,
    void *info_common
);

int asft_kdf(
    struct asft_key *key,
    void *keymat,
    size_t keymat_len,
    void *info_common
);

#endif
