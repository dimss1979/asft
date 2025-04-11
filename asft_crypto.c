#include <stddef.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/random.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/hmac.h>

#include "asft_proto.h"
#include "asft_misc.h"

#include "asft_crypto.h"

#define CHACHA20_MAX_IVLEN 16

_Static_assert(ASFT_TAG_LEN + 4 <= CHACHA20_MAX_IVLEN, "MAC tag must not overlap chacha20 32-bit counter");

char *asft_crypto_init_key_req  = "Initial key for request";
char *asft_crypto_init_key_resp = "Initial key for response";

struct asft_ecdh {
    EVP_PKEY *pkey;
};

static char *network_name = NULL;

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
    if (!network_name) {
        asft_error("Network name not specified\n");
        goto error;
    }

    return 0;

error:

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
    struct asft_key *skey_req,
    struct asft_key *skey_resp
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

    if (asft_kdf(skey_req, shared_secret, sizeof(shared_secret), "Session key for request"))
        goto error;

    if (asft_kdf(skey_resp, shared_secret, sizeof(shared_secret), "Session key for response"))
        goto error;

    rv = 0;

error:

    EVP_PKEY_free(peer_key);
    EVP_PKEY_CTX_free(pctx);
    ecdh_cleanup(c);
    *ecdh = NULL;

    return rv;
}

int asft_pkt_encrypt(
    void *cpkt,
    void *pkt,
    size_t pkt_len,
    struct asft_key *key
) {
    int rv = -1;
    int tmplen;
    unsigned char *from = pkt + ASFT_TAG_LEN;
    unsigned char *to = cpkt + ASFT_TAG_LEN;
    size_t enc_len = pkt_len - ASFT_TAG_LEN;
    unsigned char nonce[CHACHA20_MAX_IVLEN] = {0};

    EVP_CIPHER_CTX *ctx = NULL;

    if (pkt_len > sizeof(asft_pkt))
        goto error;

    if (pkt_len < ASFT_TAG_LEN + 1)
        goto error;

    unsigned char *hmac = HMAC(EVP_blake2b512(), key->auth, sizeof(key->auth), from, enc_len, NULL, NULL);

    if (!hmac)
        goto error;

    memcpy(cpkt, hmac, ASFT_TAG_LEN);
    memcpy(nonce + 4, hmac, ASFT_TAG_LEN);

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        asft_error("Encryption cipher ctx failed\n");
        goto error;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_chacha20(), NULL, key->enc, nonce) != 1)
        goto error;

    if (EVP_EncryptUpdate(ctx, to, &tmplen, from, enc_len) != 1)
        goto error;

    if (EVP_EncryptFinal_ex(ctx, to + tmplen, &tmplen) != 1)
        goto error;

    rv = 0;

error:

    if (ctx)
        EVP_CIPHER_CTX_free(ctx);

    return rv;
}

int asft_pkt_decrypt(
    void *pkt,
    void *cpkt,
    size_t cpkt_len,
    struct asft_key *key
) {
    int rv = -1;
    int tmplen;
    unsigned char *from = cpkt + ASFT_TAG_LEN;
    unsigned char *to = pkt + ASFT_TAG_LEN;
    size_t dec_len = cpkt_len - ASFT_TAG_LEN;
    unsigned char nonce[CHACHA20_MAX_IVLEN] = {0};

    EVP_CIPHER_CTX *ctx = NULL;

    if (cpkt_len < ASFT_TAG_LEN + 1)
        goto error;

    memcpy(nonce + 4, cpkt, ASFT_TAG_LEN);

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        asft_error("Decryption cipher ctx failed\n");
        goto error;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_chacha20(), NULL, key->enc, nonce) != 1)
        goto error;

    if (EVP_DecryptUpdate(ctx, to, &tmplen, from, dec_len) != 1)
        goto error;

    if (EVP_DecryptFinal_ex(ctx, to + tmplen, &tmplen) != 1)
        goto error;

    unsigned char *hmac = HMAC(EVP_blake2b512(), key->auth, sizeof(key->auth), to, dec_len, NULL, NULL);

    if (!hmac || CRYPTO_memcmp(hmac, cpkt, ASFT_TAG_LEN))
        goto error;

    rv = 0;

error:

    if (ctx)
        EVP_CIPHER_CTX_free(ctx);

    return rv;
}

int asft_kdf_once(
    unsigned char *key,
    void *keymat,
    size_t keymat_len,
    void *info_common,
    void *info
) {
    int rv = 1;
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kctx = NULL;
    OSSL_PARAM params[6], *p = params;

    if (!network_name || !keymat || !info)
        goto error;

    kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (!kdf)
        goto error;

    kctx = EVP_KDF_CTX_new(kdf);
    if (!kctx)
        goto error;

    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, SN_blake2b512, strlen(SN_blake2b512));
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, keymat, keymat_len);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, network_name, strlen(network_name));
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, info_common, strlen(info_common));
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, info, strlen(info));
    *p = OSSL_PARAM_construct_end();

    if (EVP_KDF_derive(kctx, key, ASFT_KEY_LEN, params) != 1)
        goto error;

    rv = 0;

error:

    if (kctx)
        EVP_KDF_CTX_free(kctx);
    if (kdf)
        EVP_KDF_free(kdf);

    return rv;
}

int asft_kdf(
    struct asft_key *key,
    void *keymat,
    size_t keymat_len,
    void *info_common
) {
    int rv;

    if ((rv = asft_kdf_once(key->enc, keymat, keymat_len, info_common, "Encryption")))
        return rv;
    if ((rv = asft_kdf_once(key->auth, keymat, keymat_len, info_common, "Authentication")))
        return rv;
    if ((rv = asft_kdf_once(key->auth_blob, keymat, keymat_len, info_common, "BLOB Authentication")))
        return rv;

    return rv;
}
