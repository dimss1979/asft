#ifndef _ASFT_CRYPTO_H_
#define _ASFT_CRYPTO_H_

#define ASFT_CRYPTO_KEY_SIZE 32

size_t asft_crypto_init(size_t pkt_len_max);
void asft_crypto_cleanup();

int asft_packet_encrypt(
    unsigned char **cpkt_ptr,
    size_t *cpkt_len_ptr,
    unsigned char *pkt,
    size_t pkt_len,
    unsigned char *key
);

int asft_packet_decrypt(
    unsigned char **pkt_ptr,
    size_t *pkt_len_ptr,
    unsigned char *_cpkt,
    size_t cpkt_len,
    unsigned char *key
);

#endif
