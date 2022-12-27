#include <stddef.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/random.h>
#include <openssl/evp.h>

#include "asft_proto.h"

#include "asft_crypto.h"

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
    asft_packet *pkt,
    size_t pkt_len,
    unsigned char *key
) {
    int rv = 0;
    int outlen, tmplen;
    unsigned char *from = (unsigned char *) &pkt->cmd.cmd;
    unsigned char *to = (unsigned char *) &g_pkt->cmd.cmd;
    struct asft_base_hdr *h = &g_pkt->cmd.base;
    size_t enc_len = pkt_len - sizeof(*h);

    if (!g_ctx) {
        rv = -EINVAL;
        goto end;
    }

    if (pkt_len > sizeof(*pkt)) {
        rv = -EINVAL;
        goto end;
    }

    memcpy(g_pkt, pkt, pkt_len);

    do {
        rv = getrandom(h->nonce, sizeof(h->nonce), 0);
    } while(rv == -EINTR);
    if (rv < 0)
        goto end;
    rv = 0;

    EVP_EncryptInit(g_ctx, EVP_chacha20_poly1305(), key, h->nonce);
    if (!EVP_EncryptUpdate(g_ctx, NULL, &outlen, &h->dst_addr, sizeof(h->dst_addr))) {
        rv = -EINVAL;
        goto end;
    }
    if (!EVP_EncryptUpdate(g_ctx, to, &outlen, from, enc_len)) {
        rv = -EINVAL;
        goto end;
    }
    if (!EVP_EncryptFinal(g_ctx, &to[outlen], &tmplen)) {
        rv = -EINVAL;
        goto end;
    }
    if (!EVP_CIPHER_CTX_ctrl(g_ctx, EVP_CTRL_AEAD_GET_TAG, ASFT_TAG_LEN, h->tag)) {
        rv = -EINVAL;
        goto end;
    }

end:

    if (!rv) {
        *cpkt_ptr = g_pkt;
    } else {
        fprintf(stderr, "Encryption failed\n");
    }

    return rv;
}

int asft_packet_decrypt(
    asft_packet **pkt_ptr,
    asft_packet *cpkt,
    size_t cpkt_len,
    unsigned char *key
) {
    int rv = 0;
    int outlen, tmplen;
    unsigned char *from = (unsigned char *) &cpkt->cmd.cmd;
    unsigned char *to = (unsigned char *) &g_pkt->cmd.cmd;
    struct asft_base_hdr *h = &cpkt->cmd.base;
    size_t dec_len = cpkt_len - sizeof(*h);

    if (!g_ctx) {
        rv = -EINVAL;
        goto end;
    }

    if (cpkt_len > sizeof(*cpkt)) {
        rv = -EINVAL;
        goto end;
    }

    memcpy(g_pkt, cpkt, cpkt_len);

    EVP_DecryptInit(g_ctx, EVP_chacha20_poly1305(), key, h->nonce);
    if (!EVP_CIPHER_CTX_ctrl(g_ctx, EVP_CTRL_AEAD_SET_TAG, ASFT_TAG_LEN, h->tag)) {
        rv = -EINVAL;
        goto end;
    }
    if (!EVP_DecryptUpdate(g_ctx, NULL, &outlen, &h->dst_addr, sizeof(h->dst_addr))) {
        rv = -EINVAL;
        goto end;
    }
    if (!EVP_DecryptUpdate(g_ctx, to, &outlen, from, dec_len)) {
        rv = -EINVAL;
        goto end;
    }
    if (!EVP_DecryptFinal(g_ctx, &to[outlen], &tmplen)) {
        rv = -EINVAL;
        goto end;
    }

end:

    if (!rv) {
        *pkt_ptr = g_pkt;
    } else {
        fprintf(stderr, "Decryption failed\n");
    }

    return rv;
}
