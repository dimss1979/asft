#define _GNU_SOURCE

#include <stddef.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/hmac.h>
#include <unistd.h>
#include <assert.h>
#include <stdbool.h>

#include "asft_proto.h"
#include "asft_misc.h"

#include "asft_crypto.h"

#define CHACHA_KEY_SIZE 32
#define CHACHA_CTR_SIZE 16

_Static_assert(ASFT_TAG_LEN + 4 <= CHACHA_CTR_SIZE, "MAC tag must not overlap chacha20 32-bit counter");

struct asft_key {
    unsigned char enc[CHACHA_KEY_SIZE];
    unsigned char enc_of_nonce[CHACHA_KEY_SIZE];
};

struct asft_crypto_ctx {
    uint64_t timestamp;
    uint8_t master_key[64];
};

union ts {
    uint64_t be;
    uint8_t bytes[8];
};

static int scrypt(
    void *key,
    size_t key_len,
    void *password
) {
    int rv = 1;
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kctx = NULL;
    OSSL_PARAM params[6], *p = params;

    // Random
    char salt[] = "QEf6AJSdvz4RH+mswss1KdaUF/F0UgIhLDvXeljxvR5Vt7TcV0PCPVCxvKJcY/DtAMUONzgSNc1p"
        "WxWRBC0lB8fmRVHoMVz4gjtgJ0TDESGz4/vKl+INTuuQ1A5iBGz3byHekaZRBtKMhZO1Y7a/VGQK"
        "7ZsBBArBkMYJpJ5NphE=";
    uint64_t param_N = 1024;
    uint32_t param_r = 8;
    uint32_t param_p = 16;

    if (!key || !key_len || !password)
        goto error;

    kdf = EVP_KDF_fetch(NULL, "SCRYPT", NULL);
    if (!kdf)
        goto error;

    kctx = EVP_KDF_CTX_new(kdf);
    if (!kctx)
        goto error;

    *p++ = OSSL_PARAM_construct_uint64(OSSL_KDF_PARAM_SCRYPT_N, &param_N);
    *p++ = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_SCRYPT_R, &param_r);
    *p++ = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_SCRYPT_P, &param_p);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, salt, strlen(salt));
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD, password, strlen(password));
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

static int chacha20(
    unsigned char *out,
    unsigned char *in,
    size_t len,
    unsigned char *key,
    unsigned char *iv
)
{
    int rv = 1;
    int tmplen;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        goto error;

    if (EVP_EncryptInit_ex(ctx, EVP_chacha20(), NULL, key, iv) != 1)
        goto error;

    if (EVP_EncryptUpdate(ctx, out, &tmplen, in, len) != 1)
        goto error;

    if (EVP_EncryptFinal_ex(ctx, out + tmplen, &tmplen) != 1)
        goto error;

    rv = 0;

error:

    if (ctx)
        EVP_CIPHER_CTX_free(ctx);

    return rv;
}

static int chaSIV_H(
    unsigned char *T,
    unsigned char *K,
    unsigned char *N,
    size_t N_len,
    unsigned char *M,
    size_t M_len,
    unsigned char *AD,
    size_t AD_len
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

    if (EVP_DigestUpdate(mdctx, K, CHACHA_KEY_SIZE) != 1) {
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
    if (EVP_DigestUpdate(mdctx, AD, AD_len) != 1) {
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

    // From OpenSSL doc:
    // BLAKE2SMAC max key size == chacha20 key size (32 bytes)

    if (EVP_MAC_init(ctx, K, CHACHA_KEY_SIZE, NULL) != 1) {
        asft_error("Cannot initialize MAC\n");
        goto error;
    }

    if (EVP_MAC_update(ctx, N, N_len) != 1) {
        asft_error("Cannot update MAC of nonce\n");
        goto error;
    }

    size_t output_len = 0;
    if (EVP_MAC_final(ctx, Ke, &output_len, CHACHA_KEY_SIZE) != 1) {
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

static int chaSIV_encrypt(
    void *cpkt,
    void *pkt,
    size_t pkt_len,
    struct asft_key *key,
    size_t N_len,
    void *AD,
    size_t AD_len
) {
    int rv = -1;
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

    if (chaSIV_H(T, K, N, N_len, M, M_len, AD, AD_len)) {
        asft_error("Encryption H() failed\n");
        goto error;
    }

    unsigned char E_nonce[CHACHA_CTR_SIZE] = {0};
    memcpy(E_nonce + 4, T, ASFT_TAG_LEN);

    unsigned char Ke[CHACHA_KEY_SIZE] = {0};
    if (chaSIV_F(Ke, K, N, N_len)) {
        asft_error("Encryption F() failed\n");
        goto error;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        asft_error("Encryption cipher ctx failed\n");
        goto error;
    }

    if (chacha20(C, M, M_len, Ke, E_nonce))
        goto error;

    // Additional step - nonce encryption
    // Not a part of chaSIV
    if (chacha20(Nc, N, N_len, key->enc_of_nonce, E_nonce))
        goto error;

    rv = 0;

error:

    if (ctx)
        EVP_CIPHER_CTX_free(ctx);

    return rv;
}

static int chaSIV_decrypt(
    void *pkt,
    void *cpkt,
    size_t cpkt_len,
    struct asft_key *key,
    size_t N_len,
    void *AD,
    size_t AD_len
) {
    int rv = -1;
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

    unsigned char E_nonce[CHACHA_CTR_SIZE] = {0};
    memcpy(E_nonce + 4, T, ASFT_TAG_LEN);

    // Additional step - nonce decryption
    // Not a part of chaSIV
    if (chacha20(N, Nc, N_len, key->enc_of_nonce, E_nonce))
        goto error;

    unsigned char Ke[CHACHA_KEY_SIZE] = {0};
    if (chaSIV_F(Ke, K, N, N_len)) {
        asft_error("Decryption F() failed\n");
        goto error;
    }

    if (chacha20(M, C, C_len, Ke, E_nonce))
        goto error;

    unsigned char T_local[ASFT_TAG_LEN];
    if (chaSIV_H(T_local, K, N, N_len, M, C_len, AD, AD_len)) {
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

struct asft_crypto_ctx *asft_crypto_ctx_init(char *password)
{
    struct asft_crypto_ctx *ctx;

    ctx = malloc(sizeof(*ctx));
    assert(ctx);
    memset(ctx, 0, sizeof(*ctx));

    ctx->timestamp = asft_timestamp();
    int rv = scrypt(ctx->master_key, sizeof(ctx->master_key), password);
    if (rv)
        goto error;

    return ctx;

error:

    free(ctx);

    return NULL;
}

int asft_encrypt_req(
    struct asft_crypto_ctx *ctx,
    asft_pkt *cpkt,
    asft_pkt *pkt,
    size_t pkt_len
) {
    int rv = 1;

    union ts t;
    ctx->timestamp = asft_timestamp();
    t.be = htobe64(ctx->timestamp);
    memcpy(pkt->b.timestamp, &t.bytes[ASFT_TS_HIDE], ASFT_TS_LEN);

    struct asft_key key;

    rv = HKDF(
        key.enc, sizeof(key.enc),
        ctx->master_key, sizeof(ctx->master_key),
        "asft-request-key"
    );
    if (rv)
        goto error;

    rv = HKDF(
        key.enc_of_nonce, sizeof(key.enc_of_nonce),
        ctx->master_key, sizeof(ctx->master_key),
        "asft-request-key-for-nonce"
    );
    if (rv)
        goto error;

    rv = chaSIV_encrypt(cpkt, pkt, pkt_len, &key, sizeof(pkt->b.timestamp), t.bytes, ASFT_TS_HIDE);
    if (rv)
        goto error;

    rv = 0;

error:

    return rv;
}

int asft_decrypt_req(
    struct asft_crypto_ctx *ctx,
    asft_pkt *pkt,
    asft_pkt *cpkt,
    size_t cpkt_len
) {
    int rv = 1;
    struct asft_key key;

    rv = HKDF(
        key.enc, sizeof(key.enc),
        ctx->master_key, sizeof(ctx->master_key),
        "asft-request-key"
    );
    if (rv)
        goto error;

    rv = HKDF(
        key.enc_of_nonce, sizeof(key.enc_of_nonce),
        ctx->master_key, sizeof(ctx->master_key),
        "asft-request-key-for-nonce"
    );
    if (rv)
        goto error;

    union ts t;
    t.be = htobe64(asft_timestamp());

    rv = chaSIV_decrypt(pkt, cpkt, cpkt_len, &key, sizeof(pkt->b.timestamp), t.bytes, ASFT_TS_HIDE);
    if (!rv)
        goto decrypted;

    t.be = htobe64(asft_timestamp() - (1ULL << (ASFT_TS_LEN * 8)));

    rv = chaSIV_decrypt(pkt, cpkt, cpkt_len, &key, sizeof(pkt->b.timestamp), t.bytes, ASFT_TS_HIDE);
    if (!rv)
        goto decrypted;

    t.be = htobe64(asft_timestamp() + (1ULL << (ASFT_TS_LEN * 8)));

    rv = chaSIV_decrypt(pkt, cpkt, cpkt_len, &key, sizeof(pkt->b.timestamp), t.bytes, ASFT_TS_HIDE);
    if (!rv)
        goto decrypted;

    rv = 1;
    goto error;

decrypted:

    memcpy(&t.bytes[ASFT_TS_HIDE], pkt->b.timestamp, ASFT_TS_LEN);
    uint64_t timestamp_new = be64toh(t.be);

    if (timestamp_new <= ctx->timestamp) {
        asft_error("Replay detected\n");
        rv = 1;
        goto error;
    }

    ctx->timestamp = timestamp_new;
    rv = 0;

error:

    return rv;
}

int asft_encrypt_resp(
    struct asft_crypto_ctx *ctx,
    asft_pkt *cpkt,
    asft_pkt *pkt,
    size_t pkt_len
) {
    int rv = 1;

    union ts t;
    t.be = htobe64(ctx->timestamp);
    memcpy(pkt->b.timestamp, &t.bytes[ASFT_TS_HIDE], ASFT_TS_LEN);

    struct asft_key key;

    rv = HKDF(
        key.enc, sizeof(key.enc),
        ctx->master_key, sizeof(ctx->master_key),
        "asft-response-key"
    );
    if (rv)
        goto error;

    rv = HKDF(
        key.enc_of_nonce, sizeof(key.enc_of_nonce),
        ctx->master_key, sizeof(ctx->master_key),
        "asft-response-key-for-nonce"
    );
    if (rv)
        goto error;

    rv = chaSIV_encrypt(cpkt, pkt, pkt_len, &key, sizeof(pkt->b.timestamp), t.bytes, ASFT_TS_HIDE);
    if (rv)
        goto error;

    rv = 0;

error:

    return rv;
}

int asft_decrypt_resp(
    struct asft_crypto_ctx *ctx,
    asft_pkt *pkt,
    asft_pkt *cpkt,
    size_t cpkt_len
) {
    int rv = 1;

    struct asft_key key;

    rv = HKDF(
        key.enc, sizeof(key.enc),
        ctx->master_key, sizeof(ctx->master_key),
        "asft-response-key"
    );
    if (rv)
        goto error;

    rv = HKDF(
        key.enc_of_nonce, sizeof(key.enc_of_nonce),
        ctx->master_key, sizeof(ctx->master_key),
        "asft-response-key-for-nonce"
    );
    if (rv)
        goto error;

    union ts t;
    t.be = htobe64(ctx->timestamp);

    rv = chaSIV_decrypt(pkt, cpkt, cpkt_len, &key, sizeof(pkt->b.timestamp), t.bytes, ASFT_TS_HIDE);
    if (rv)
        goto error;

    memcpy(&t.bytes[ASFT_TS_HIDE], pkt->b.timestamp, ASFT_TS_LEN);
    uint64_t timestamp_received = be64toh(t.be);

    if (timestamp_received != ctx->timestamp) {
        asft_error("Replay detected\n");
        rv = 1;
        goto error;
    }

    rv = 0;

error:

    return rv;
}
