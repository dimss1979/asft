#include <stddef.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/random.h>
#include <openssl/evp.h>

#include "asft_proto.h"

#include "asft_crypto.h"

#define CHACHA20_POLY1305_MAX_IVLEN 12

static asft_packet *g_pkt = NULL;
static EVP_CIPHER_CTX *g_ctx = NULL;

static void asft_crypto_cleanup()
{
    if (g_ctx) {
        EVP_CIPHER_CTX_free(g_ctx);
        g_ctx = NULL;
    }

    if (g_pkt) {
        free(g_pkt);
        g_pkt = NULL;
    }
}

size_t asft_crypto_init()
{
    asft_crypto_cleanup();

    g_pkt = malloc(sizeof(*g_pkt));
    if (!g_pkt) {
        fprintf(stderr, "Cannot allocate temporary packet buffer\n");
        goto error;
    }

    g_ctx = EVP_CIPHER_CTX_new();
    if (!g_ctx) {
        fprintf(stderr, "Cannot allocate OpenSSL cipher context\n");
        goto error;
    }

    return 0;

error:

    asft_crypto_cleanup();

    return -1;
}

int asft_packet_encrypt(
    asft_packet **cpkt_ptr,
    void *pkt,
    size_t pkt_len,
    unsigned char *key
) {
    int outlen, tmplen;
    struct asft_base_hdr *h = (struct asft_base_hdr*) pkt;
    unsigned char *from = (unsigned char *) &h->command;
    unsigned char *to = (unsigned char *) &g_pkt->base.command;
    size_t enc_len = pkt_len - sizeof(*h) + sizeof(h->command);
    unsigned char nonce[CHACHA20_POLY1305_MAX_IVLEN] = {0};

    if (!g_ctx)
        goto error;

    if (pkt_len > sizeof(asft_packet))
        goto error;

    if (pkt_len < sizeof(struct asft_base_hdr))
        goto error;

    memcpy(g_pkt, pkt, pkt_len - enc_len);
    memcpy(nonce, &h->packet_number, sizeof(h->packet_number));

    if (!EVP_EncryptInit_ex(g_ctx, EVP_chacha20_poly1305(), NULL, key, nonce))
        goto error;

    if (!EVP_EncryptUpdate(g_ctx, NULL, &outlen, &h->dst_addr, sizeof(h->dst_addr)))
        goto error;

    if (!EVP_EncryptUpdate(g_ctx, to, &outlen, from, enc_len))
        goto error;

    if (!EVP_EncryptFinal_ex(g_ctx, &to[outlen], &tmplen))
        goto error;

    if (!EVP_CIPHER_CTX_ctrl(g_ctx, EVP_CTRL_AEAD_GET_TAG, ASFT_TAG_LEN, &g_pkt->base.tag))
        goto error;

    *cpkt_ptr = g_pkt;
    return 0;

error:

    return -1;
}

int asft_packet_decrypt(
    asft_packet **pkt_ptr,
    asft_packet *cpkt,
    size_t cpkt_len,
    unsigned char *key
) {
    int outlen, tmplen;
    struct asft_base_hdr *h = &cpkt->base;
    unsigned char *from = (unsigned char *) &h->command;
    unsigned char *to = (unsigned char *) &g_pkt->base.command;
    size_t dec_len = cpkt_len - sizeof(*h) + sizeof(h->command);
    unsigned char nonce[CHACHA20_POLY1305_MAX_IVLEN] = {0};

    if (!g_ctx)
        goto error;

    if (cpkt_len > sizeof(*cpkt))
        goto error;

    if (cpkt_len < sizeof(struct asft_base_hdr))
        goto error;

    memcpy(g_pkt, cpkt, cpkt_len - dec_len);
    memcpy(nonce, &h->packet_number, sizeof(h->packet_number));

    if (!EVP_DecryptInit_ex(g_ctx, EVP_chacha20_poly1305(), NULL, key, nonce))
        goto error;

    if (!EVP_CIPHER_CTX_ctrl(g_ctx, EVP_CTRL_AEAD_SET_TAG, ASFT_TAG_LEN, h->tag))
        goto error;

    if (!EVP_DecryptUpdate(g_ctx, NULL, &outlen, &h->dst_addr, sizeof(h->dst_addr)))
        goto error;

    if (!EVP_DecryptUpdate(g_ctx, to, &outlen, from, dec_len))
        goto error;

    if (!EVP_DecryptFinal_ex(g_ctx, &to[outlen], &tmplen))
        goto error;

    *pkt_ptr = g_pkt;
    return 0;

error:

    return -1;
}
