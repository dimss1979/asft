#include <stddef.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/random.h>
#include <openssl/evp.h>

#include "asft_crypto.h"

#define CP_NONCE_SIZE 12
#define CP_TAG_SIZE   16
#define CP_KEY_SIZE   ASFT_CRYPTO_KEY_SIZE

struct _asft_cpacket {
    unsigned char nonce[CP_NONCE_SIZE];
    unsigned char tag[CP_TAG_SIZE];
    unsigned char cdata[];
} __attribute__((packed));

static asft_cpacket g_cpkt = NULL;
static size_t g_cpkt_len_max = 0;
static unsigned char *g_pkt = NULL;
static size_t g_pkt_len_max = 0;
EVP_CIPHER_CTX *g_ctx = NULL;

size_t asft_crypto_init(size_t pkt_len_max)
{
    size_t cpkt_len_max = sizeof(*g_cpkt) + pkt_len_max;

    asft_crypto_cleanup();

    g_pkt = malloc(pkt_len_max);
    if (!g_pkt) {
        fprintf(stderr, "Cannot allocate decrypted packet\n");
        goto error;
    }
    g_pkt_len_max = pkt_len_max;

    g_cpkt = malloc(cpkt_len_max);
    if (!g_cpkt) {
        fprintf(stderr, "Cannot allocate encrypted packet\n");
        goto error;
    }
    g_cpkt_len_max = cpkt_len_max;

    g_ctx = EVP_CIPHER_CTX_new();
    if (!g_ctx) {
        fprintf(stderr, "Cannot allocate OpenSSL cipher context\n");
        goto error;
    }

    return cpkt_len_max;

error:

    asft_crypto_cleanup();

    return 0;
}

void asft_crypto_cleanup()
{
    if (g_ctx) {
        EVP_CIPHER_CTX_free(g_ctx);
        g_ctx = NULL;
    }

    if (g_cpkt) {
        free(g_cpkt);
        g_cpkt = NULL;
        g_cpkt_len_max = 0;
    }

    if (g_pkt) {
        free(g_pkt);
        g_pkt = NULL;
        g_pkt_len_max = 0;
    }
}

int asft_packet_encrypt(
    unsigned char **cpkt_ptr,
    size_t *cpkt_len_ptr,
    unsigned char *pkt,
    size_t pkt_len,
    unsigned char *key
) {
    int rv = 0;
    size_t cpkt_len = sizeof(*g_cpkt) + pkt_len;
    int outlen, tmplen;

    if (!g_ctx) {
        rv = -EINVAL;
        goto end;
    }

    do {
        rv = getrandom(g_cpkt->nonce, sizeof(g_cpkt->nonce), 0);
    } while(rv == -EINTR);
    if (rv < 0) {
        goto end;
    }
    rv = 0;

    EVP_EncryptInit(g_ctx, EVP_chacha20_poly1305(), key, g_cpkt->nonce);
    if (!EVP_EncryptUpdate(g_ctx, g_cpkt->cdata, &outlen, pkt, pkt_len)) {
        rv = -EINVAL;
        goto end;
    }
    if (!EVP_EncryptFinal(g_ctx, &g_cpkt->cdata[outlen], &tmplen)) {
        rv = -EINVAL;
        goto end;
    }
    if (!EVP_CIPHER_CTX_ctrl(g_ctx, EVP_CTRL_AEAD_GET_TAG, CP_TAG_SIZE, g_cpkt->tag)) {
        rv = -EINVAL;
        goto end;
    }

end:

    if (!rv) {
        *cpkt_ptr = (unsigned char*) g_cpkt;
        *cpkt_len_ptr = cpkt_len;
    } else {
        fprintf(stderr, "Encryption failed\n");
    }

    return rv;
}

int asft_packet_decrypt(
    unsigned char **pkt_ptr,
    size_t *pkt_len_ptr,
    unsigned char *_cpkt,
    size_t cpkt_len,
    unsigned char *key
) {
    int rv = 0;
    asft_cpacket cpkt = (asft_cpacket) _cpkt;
    size_t pkt_len = cpkt_len - sizeof(*cpkt);
    int outlen, tmplen;

    if (cpkt_len <= sizeof(*cpkt)) {
        rv = -EINVAL;
        goto end;
    }

    if (!g_ctx) {
        rv = -EINVAL;
        goto end;
    }

    EVP_DecryptInit(g_ctx, EVP_chacha20_poly1305(), key, cpkt->nonce);
    if (!EVP_CIPHER_CTX_ctrl(g_ctx, EVP_CTRL_AEAD_SET_TAG, CP_TAG_SIZE, cpkt->tag)) {
        rv = -EINVAL;
        goto end;
    }
    if (!EVP_DecryptUpdate(g_ctx, g_pkt, &outlen, cpkt->cdata, pkt_len)) {
        rv = -EINVAL;
        goto end;
    }
    if (!EVP_DecryptFinal(g_ctx, &g_pkt[outlen], &tmplen)) {
        rv = -EINVAL;
        goto end;
    }

end:

    if (!rv) {
        *pkt_ptr = g_pkt;
        *pkt_len_ptr = pkt_len;
    } else {
        fprintf(stderr, "Decryption failed\n");
    }

    return rv;
}
