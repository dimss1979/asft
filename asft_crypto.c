#include <stddef.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/random.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>

#include "asft_proto.h"
#include "asft_misc.h"

#include "asft_crypto.h"

#define CHACHA20_POLY1305_MAX_IVLEN 12
#define CHACHA20_MAX_IVLEN 16

struct asft_ecdh {
    EVP_PKEY *pkey;
};

static asft_packet *g_pkt = NULL;
static EVP_CIPHER_CTX *g_ctx = NULL;
static char *network_name = NULL;

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

static void ecdh_cleanup(struct asft_ecdh *ecdh)
{
    if (ecdh) {
        if (ecdh->pkey) {
            EVP_PKEY_free(ecdh->pkey);
        }
        free(ecdh);
    }
}

size_t asft_crypto_init()
{
    asft_crypto_cleanup();

    g_pkt = malloc(sizeof(*g_pkt));
    if (!g_pkt) {
        asft_error("Cannot allocate temporary packet buffer\n");
        goto error;
    }

    g_ctx = EVP_CIPHER_CTX_new();
    if (!g_ctx) {
        asft_error("Cannot allocate OpenSSL cipher context\n");
        goto error;
    }

    if (!network_name) {
        asft_error("Network name not specified\n");
        goto error;
    }

    return 0;

error:

    asft_crypto_cleanup();

    return -1;
}

int asft_crypto_set_network_name(char *new_network_name)
{
    if (network_name) {
        free(network_name);
    }
    network_name = strdup(new_network_name);
    if (network_name) {
        return 0;
    }
    return -1;
}

int asft_ecdh_prepare(
    struct asft_ecdh **ecdh,
    unsigned char *pkey_out
) {
    struct asft_ecdh *c = NULL;
    size_t len = ASFT_ECDH_KEY_LEN;
    EVP_PKEY_CTX *pctx = NULL;
    int rv = 1;

    c = malloc(sizeof(*c));
    if (!c)
        goto error;
    memset(c, 0, sizeof(*c));

    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (!pctx)
        goto error;

    if (EVP_PKEY_keygen_init(pctx) != 1)
        goto error;

    if (EVP_PKEY_keygen(pctx, &c->pkey) != 1)
        goto error;

    if (EVP_PKEY_get_raw_public_key(c->pkey, pkey_out, &len) != 1)
        goto error;

    if (*ecdh) {
        ecdh_cleanup(*ecdh);
    }
    *ecdh = c;
    rv = 0;

error:

    EVP_PKEY_CTX_free(pctx);
    if (rv) {
        ecdh_cleanup(c);
    }

    return rv;
}

int asft_ecdh_process(
    struct asft_ecdh **ecdh,
    unsigned char *peer_pkey_in,
    struct asft_key *skey_out
) {
    int rv = 1;
    struct asft_ecdh *c = *ecdh;
    EVP_PKEY *peer_key = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    size_t skeylen;
    unsigned char shared_secret[ASFT_ECDH_KEY_LEN];

    if (!c)
        goto error;

    peer_key = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, peer_pkey_in, ASFT_ECDH_KEY_LEN);
    if (!peer_key)
        goto error;

    pctx = EVP_PKEY_CTX_new(c->pkey, NULL);
    if (!pctx)
        goto error;

    if (EVP_PKEY_derive_init(pctx) != 1)
        goto error;

    if (EVP_PKEY_derive_set_peer(pctx, peer_key) <= 0)
        goto error;

    if (EVP_PKEY_derive(pctx, NULL, &skeylen) <= 0)
        goto error;

    if (skeylen != sizeof(shared_secret))
        goto error;

    if (EVP_PKEY_derive(pctx, shared_secret, &skeylen) <= 0)
        goto error;

    if (asft_kdf(skey_out, shared_secret, sizeof(shared_secret)))
        goto error;

    rv = 0;

error:

    EVP_PKEY_free(peer_key);
    EVP_PKEY_CTX_free(pctx);
    ecdh_cleanup(c);
    *ecdh = NULL;

    return rv;
}

int asft_packet_encrypt(
    asft_packet **cpkt_ptr,
    void *pkt,
    size_t pkt_len,
    struct asft_key *key
) {
    int outlen, tmplen;
    struct asft_base_hdr *h = (struct asft_base_hdr*) pkt;
    unsigned char *from = (unsigned char *) &h->command;
    unsigned char *to = (unsigned char *) &g_pkt->base.command;
    size_t enc_len = pkt_len - sizeof(*h) + sizeof(h->command);
    unsigned char nonce_inner[CHACHA20_POLY1305_MAX_IVLEN] = {0};
    unsigned char nonce_outer[CHACHA20_MAX_IVLEN] = {0};

    if (!g_ctx)
        goto error;

    if (pkt_len > sizeof(asft_packet))
        goto error;

    if (pkt_len < sizeof(struct asft_base_hdr))
        goto error;

    memcpy(nonce_inner, h->pn, sizeof(h->pn));

    if (!EVP_EncryptInit_ex(g_ctx, EVP_chacha20_poly1305(), NULL, key->inner, nonce_inner))
        goto error;

    if (!EVP_EncryptUpdate(g_ctx, to, &outlen, from, enc_len))
        goto error;

    if (!EVP_EncryptFinal_ex(g_ctx, &to[outlen], &tmplen))
        goto error;

    if (!EVP_CIPHER_CTX_ctrl(g_ctx, EVP_CTRL_AEAD_GET_TAG, ASFT_TAG_LEN, &g_pkt->base.tag))
        goto error;

    memcpy(nonce_outer, &g_pkt->base.tag, sizeof(g_pkt->base.tag));

    if (!EVP_EncryptInit_ex(g_ctx, EVP_chacha20(), NULL, key->outer, nonce_outer))
        goto error;

    if (!EVP_EncryptUpdate(g_ctx, g_pkt->base.pn, &outlen, h->pn, sizeof(h->pn)))
        goto error;

    if (!EVP_EncryptFinal_ex(g_ctx, &g_pkt->base.pn[outlen], &tmplen))
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
    struct asft_key *key
) {
    int outlen, tmplen;
    struct asft_base_hdr *h = &cpkt->base;
    unsigned char *from = (unsigned char *) &h->command;
    unsigned char *to = (unsigned char *) &g_pkt->base.command;
    size_t dec_len = cpkt_len - sizeof(*h) + sizeof(h->command);
    unsigned char nonce_inner[CHACHA20_POLY1305_MAX_IVLEN] = {0};
    unsigned char nonce_outer[CHACHA20_MAX_IVLEN] = {0};

    if (!g_ctx)
        goto error;

    if (cpkt_len > sizeof(*cpkt))
        goto error;

    if (cpkt_len < sizeof(struct asft_base_hdr))
        goto error;

    memcpy(nonce_outer, &h->tag, sizeof(h->tag));

    if (!EVP_DecryptInit_ex(g_ctx, EVP_chacha20(), NULL, key->outer, nonce_outer))
        goto error;

    if (!EVP_DecryptUpdate(g_ctx, g_pkt->base.pn, &outlen, h->pn, sizeof(h->pn)))
        goto error;

    if (!EVP_DecryptFinal_ex(g_ctx, &g_pkt->base.pn[outlen], &tmplen))
        goto error;

    memcpy(nonce_inner, g_pkt->base.pn, sizeof(g_pkt->base.pn));

    if (!EVP_DecryptInit_ex(g_ctx, EVP_chacha20_poly1305(), NULL, key->inner, nonce_inner))
        goto error;

    if (!EVP_CIPHER_CTX_ctrl(g_ctx, EVP_CTRL_AEAD_SET_TAG, ASFT_TAG_LEN, h->tag))
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

int asft_kdf(
    struct asft_key *key,
    void *keymat,
    size_t keymat_len
) {
    int rv = 1;
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kctx = NULL;
    OSSL_PARAM params[4], *p = params;

    if (!network_name || !keymat)
        goto error;

    kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (!kdf)
        goto error;

    kctx = EVP_KDF_CTX_new(kdf);
    if (!kctx)
        goto error;

    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, SN_sha3_512, strlen(SN_sha3_512));
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, keymat, keymat_len);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, network_name, strlen(network_name));
    *p = OSSL_PARAM_construct_end();

    if (EVP_KDF_derive(kctx, (unsigned char*) key, sizeof(*key), params) <= 0)
        goto error;

    rv = 0;

error:

    if (kctx)
        EVP_KDF_CTX_free(kctx);
    if (kdf)
        EVP_KDF_free(kdf);

    return rv;
}
