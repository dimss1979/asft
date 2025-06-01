#define _GNU_SOURCE

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
#include <unistd.h>
#include <assert.h>

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

struct keystore {
    uint32_t packet_counter;
    uint8_t have_new_key;
    uint8_t new_key[64];
    uint8_t key[64];
} __attribute__((packed));

struct asft_crypto_ctx {
    char *keystore_filename;
    struct keystore ks;
    char request_hash[64];
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

static int HKDF(
    void *key,
    size_t key_len,
    void *keymat,
    size_t keymat_len,
    void *info
) {
    int rv = 1;
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kctx = NULL;
    OSSL_PARAM params[4], *p = params;

    if (!key || !keymat || !info || !key_len || !keymat_len)
        goto error;

    kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (!kdf)
        goto error;

    kctx = EVP_KDF_CTX_new(kdf);
    if (!kctx)
        goto error;

    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, SN_blake2b512, strlen(SN_blake2b512));
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, keymat, keymat_len);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, info, strlen(info));
    *p = OSSL_PARAM_construct_end();

    if (EVP_KDF_derive(kctx, key, key_len, params) != 1)
        goto error;

    rv = 0;

error:

    if (kctx)
        EVP_KDF_CTX_free(kctx);
    if (kdf)
        EVP_KDF_free(kdf);

    return rv;
}

static int keystore_load(
    struct keystore *ks,
    char *filename
) {
    int rv = 1;
    FILE *f;

    f = fopen(filename, "r");

    if (!f)
        goto error;

    if (fread(ks, sizeof(*ks), 1, f) != 1)
        goto error;

    if (fclose(f))
        goto error;

    f = NULL;
    rv = 0;

error:

    if (f)
        fclose(f);

    return rv;
}

static int keystore_save(
    struct keystore *ks,
    char *filename
) {
    int rv = 1;
    FILE *f;
    char tmpfile[PATH_MAX + 1];

    snprintf(tmpfile, sizeof(tmpfile), "%s.tmp", filename);
    f = fopen(tmpfile, "w");

    if (!f)
        goto error;

    if (fwrite(ks, sizeof(*ks), 1, f) != 1)
        goto error;

    if (fclose(f))
        goto error;

    f = NULL;

    if (rename(tmpfile, filename))
        goto error;

    sync();
    rv = 0;

error:

    if (f)
        fclose(f);

    return rv;
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

struct asft_crypto_ctx *asft_crypto_ctx_init(char *peer_label)
{
    struct asft_crypto_ctx *ctx;

    ctx = malloc(sizeof(*ctx));
    assert(ctx);
    memset(ctx, 0, sizeof(*ctx));
    int rv = asprintf(&ctx->keystore_filename, "keystore_%s", peer_label);
    assert(rv > 0);
    if (keystore_load(&ctx->ks, ctx->keystore_filename)) {
        asft_error("Failed to load keystore %s\n", ctx->keystore_filename);
        goto error;
    }

    return ctx;

error:

    free(ctx->keystore_filename);
    free(ctx);

    return NULL;
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

static int chaSIV_H(
    unsigned char *T,
    unsigned char *K,
    unsigned char *N,
    size_t N_len,
    unsigned char *M,
    size_t M_len
)
{
    int rv = -1;

    EVP_MD *md = NULL;
    EVP_MD_CTX *mdctx = NULL;

    md = EVP_MD_fetch(NULL, "BLAKE2S-256", NULL);
    if (!md) {
        asft_error("Digest is not supported\n");
        goto error;
    }

    mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        asft_error("Cannot create digest context\n");
        goto error;
    }

    if (EVP_DigestInit_ex2(mdctx, md, NULL) != 1) {
        asft_error("Cannot initialize digest\n");
        goto error;
    }

    if (EVP_DigestUpdate(mdctx, K, ASFT_KEY_LEN) != 1) {
        asft_error("Cannot update digest\n");
        goto error;
    }
    if (EVP_DigestUpdate(mdctx, N, N_len) != 1) {
        asft_error("Cannot update digest\n");
        goto error;
    }
    if (EVP_DigestUpdate(mdctx, M, M_len) != 1) {
        asft_error("Cannot update digest\n");
        goto error;
    }

    unsigned char md_buf[64];
    unsigned int md_len;
    if (EVP_DigestFinal_ex(mdctx, md_buf, &md_len) != 1) {
        asft_error("Cannot finalize digest\n");
        goto error;
    }

    memcpy(T, md_buf, ASFT_TAG_LEN);
    rv = 0;

error:

    if (mdctx)
        EVP_MD_CTX_free(mdctx);
    if (md)
        EVP_MD_free(md);

    return rv;
}

static int chaSIV_F(
    unsigned char *Ke,
    unsigned char *K,
    unsigned char *N,
    size_t N_len
)
{
    int rv = -1;

    EVP_MAC *mac = NULL;
    EVP_MAC_CTX *ctx = NULL;

    mac = EVP_MAC_fetch(NULL, "BLAKE2SMAC", "provider=default");
    if (!mac) {
        asft_error("MAC is not supported\n");
        goto error;
    }

    ctx = EVP_MAC_CTX_new(mac);
    if (!ctx) {
        asft_error("Cannot create MAC context\n");
        goto error;
    }

    if (EVP_MAC_init(ctx, K, ASFT_KEY_LEN, NULL) != 1) {
        asft_error("Cannot initialize MAC\n");
        goto error;
    }

    if (EVP_MAC_update(ctx, N, N_len) != 1) {
        asft_error("Cannot update MAC of nonce\n");
        goto error;
    }

    size_t output_len = 0;
    if (EVP_MAC_final(ctx, Ke, &output_len, ASFT_KEY_LEN) != 1) {
        asft_error("Cannot finalize MAC of nonce\n");
        goto error;
    }

    rv = 0;

error:

    if (ctx)
        EVP_MAC_CTX_free(ctx);
    if (mac)
        EVP_MAC_free(mac);

    return rv;
}

int asft_chaSIV_encrypt(
    void *cpkt,
    void *pkt,
    size_t pkt_len,
    struct asft_key *key,
    size_t N_len
) {
    int rv = -1;
    int tmplen;
    unsigned char *M = pkt + ASFT_TAG_LEN + N_len;
    unsigned char *C = cpkt + ASFT_TAG_LEN + N_len;
    size_t M_len = pkt_len - ASFT_TAG_LEN - N_len;
    unsigned char *T = cpkt;
    unsigned char *K = key->enc;
    unsigned char *N = pkt + ASFT_TAG_LEN;
    unsigned char *Nc = cpkt + ASFT_TAG_LEN;

    EVP_CIPHER_CTX *ctx = NULL;

    if (M_len < 1)
        goto error;

    if (chaSIV_H(T, K, N, N_len, M, M_len)) {
        asft_error("Encryption H() failed\n");
        goto error;
    }

    unsigned char E_nonce[CHACHA20_MAX_IVLEN] = {0};
    memcpy(E_nonce + 4, T, ASFT_TAG_LEN);

    unsigned char Ke[ASFT_KEY_LEN] = {0};
    if (chaSIV_F(Ke, K, N, N_len)) {
        asft_error("Encryption F() failed\n");
        goto error;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        asft_error("Encryption cipher ctx failed\n");
        goto error;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_chacha20(), NULL, Ke, E_nonce) != 1)
        goto error;

    if (EVP_EncryptUpdate(ctx, C, &tmplen, M, M_len) != 1)
        goto error;

    if (EVP_EncryptFinal_ex(ctx, C + tmplen, &tmplen) != 1)
        goto error;


    {
        // Additional step - nonce encryption
        // Not a part of chaSIV

        if (EVP_EncryptInit_ex(ctx, EVP_chacha20(), NULL, key->enc_of_nonce, E_nonce) != 1)
            goto error;

        if (EVP_EncryptUpdate(ctx, Nc, &tmplen, N, N_len) != 1)
            goto error;

        if (EVP_EncryptFinal_ex(ctx, Nc + tmplen, &tmplen) != 1)
            goto error;
    }

    rv = 0;

error:

    if (ctx)
        EVP_CIPHER_CTX_free(ctx);

    return rv;
}

int asft_chaSIV_decrypt(
    void *pkt,
    void *cpkt,
    size_t cpkt_len,
    struct asft_key *key,
    size_t N_len
) {
    int rv = -1;
    int tmplen;
    unsigned char *M = pkt + ASFT_TAG_LEN + N_len;
    unsigned char *C = cpkt + ASFT_TAG_LEN + N_len;
    size_t C_len = cpkt_len - ASFT_TAG_LEN - N_len;
    unsigned char *T = cpkt;
    unsigned char *K = key->enc;
    unsigned char *N = pkt + ASFT_TAG_LEN;
    unsigned char *Nc = cpkt + ASFT_TAG_LEN;

    EVP_CIPHER_CTX *ctx = NULL;

    if (C_len < 1)
        goto error;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        asft_error("Decryption cipher ctx failed\n");
        goto error;
    }

    unsigned char E_nonce[CHACHA20_MAX_IVLEN] = {0};
    memcpy(E_nonce + 4, T, ASFT_TAG_LEN);

    {
        // Additional step - nonce decryption
        // Not a part of chaSIV

        if (EVP_DecryptInit_ex(ctx, EVP_chacha20(), NULL, key->enc_of_nonce, E_nonce) != 1)
            goto error;

        if (EVP_DecryptUpdate(ctx, N, &tmplen, Nc, N_len) != 1)
            goto error;

        if (EVP_DecryptFinal_ex(ctx, N + tmplen, &tmplen) != 1)
            goto error;
    }

    unsigned char Ke[ASFT_KEY_LEN] = {0};
    if (chaSIV_F(Ke, K, N, N_len)) {
        asft_error("Decryption F() failed\n");
        goto error;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_chacha20(), NULL, Ke, E_nonce) != 1)
        goto error;

    if (EVP_DecryptUpdate(ctx, M, &tmplen, C, C_len) != 1)
        goto error;

    if (EVP_DecryptFinal_ex(ctx, M + tmplen, &tmplen) != 1)
        goto error;

    unsigned char T_local[ASFT_TAG_LEN];
    if (chaSIV_H(T_local, K, N, N_len, M, C_len)) {
        asft_error("Decryption H() failed\n");
        goto error;
    }

    if (CRYPTO_memcmp(T_local, T, ASFT_TAG_LEN))
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
    if ((rv = asft_kdf_once(key->enc_of_nonce, keymat, keymat_len, info_common, "Encryption of nonce")))
        return rv;

    return rv;
}

int asft_set_key(
    char *filename,
    char *keymat,
    size_t keymat_len
) {
    int rv = 0;
    struct keystore ks = {0};

    rv = HKDF(
        ks.key,
        sizeof(ks.key),
        keymat,
        keymat_len,
        "asft-initial-key"
    );
    if (rv)
        goto error;

    rv = keystore_save(&ks, filename);

error:

    return rv;
}
