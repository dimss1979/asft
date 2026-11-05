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
#include <openssl/rand.h>
#include <unistd.h>
#include <assert.h>
#include <stdbool.h>

#include "asft.h"

#define CHACHA_KEY_SIZE 32
#define CHACHA_CTR_SIZE 16

_Static_assert(ASFT_TAG_LEN + 4 <= CHACHA_CTR_SIZE, "MAC tag must not overlap chacha20 32-bit counter");

struct asft_crypto_ctx {
    uint64_t timestamp;
    uint64_t session_timestamp;
    uint8_t request_key[CHACHA_KEY_SIZE];
    uint8_t response_key[CHACHA_KEY_SIZE];
    uint8_t msg_key[ASFT_MSG_DIR_COUNT][CHACHA_KEY_SIZE];
    uint8_t msg_hdr_key[ASFT_MSG_DIR_COUNT][CHACHA_KEY_SIZE];
};

static const char *const msg_key_info[ASFT_MSG_DIR_COUNT] = {
    "asft-message-key-request",
    "asft-message-key-response",
};

static const char *const msg_hdr_key_info[ASFT_MSG_DIR_COUNT] = {
    "asft-message-header-key-request",
    "asft-message-header-key-response",
};

union ts {
    uint64_t be;
    uint8_t bytes[ASFT_TS_LEN];
};

static int HKDF(
    void *key,
    size_t key_len,
    void *keymat,
    size_t keymat_len,
    void *salt,
    size_t salt_len,
    const char *info
) {
    int rv = 1;
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kctx = NULL;
    OSSL_PARAM params[5], *p = params;

    if (!key || !keymat || !salt || !info || !key_len || !keymat_len || !salt_len)
        goto error;

    kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (!kdf)
        goto error;

    kctx = EVP_KDF_CTX_new(kdf);
    if (!kctx)
        goto error;

    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, SN_blake2b512, strlen(SN_blake2b512));
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, keymat, keymat_len);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, salt, salt_len);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, (void *) info, strlen(info));
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

/*
 * chaSIV transform (committing, misuse-resistant AE), from
 * S. Chen and V. Karadzic, "Committing Authenticated Encryption: Generic
 * Transforms with Hash Functions", EUROCRYPT 2025, https://eprint.iacr.org/2025/320,
 * Section 4.2, Fig. 11. Instantiation used here:
 *
 *   F(K, N)       = BLAKE2s-MAC keyed with K (32-byte output, used as Ke)
 *   H(K, N, M)    = first 5 bytes of BLAKE2s-256(K || N || M)  (tag T)
 *   E.Enc(Ke, Ne) = ChaCha20, key Ke, counter 0, nonce Ne || 0x00 * 7
 *   Ne            = T (40 bits, zero-padded to the 96-bit ChaCha20 nonce)
 *
 * Deviations from the paper: the associated data AD is empty, and N is the
 * 64-bit timestamp, of which only the low 16 bits are sent (the receiver
 * rebuilds the rest from its clock). The paper's H is a random oracle; BLAKE2s
 * with a key prefix is used as its stand-in.
 */

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

static int blake2s_mac(
    unsigned char *out,
    size_t out_len,
    unsigned char *key,
    unsigned char *data,
    size_t data_len,
    unsigned char *additional_data,
    size_t additional_data_len
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

    if (EVP_MAC_init(ctx, key, CHACHA_KEY_SIZE, NULL) != 1) {
        asft_error("Cannot initialize MAC\n");
        goto error;
    }

    if (EVP_MAC_update(ctx, data, data_len) != 1) {
        asft_error("Cannot update MAC\n");
        goto error;
    }

    if (additional_data && additional_data_len > 0) {
        if (EVP_MAC_update(ctx, additional_data, additional_data_len) != 1) {
            asft_error("Cannot update MAC of additional data\n");
            goto error;
        }
    }

    size_t output_len = 0;
    unsigned char output[CHACHA_KEY_SIZE];
    if (EVP_MAC_final(ctx, output, &output_len, CHACHA_KEY_SIZE) != 1) {
        asft_error("Cannot finalize MAC\n");
        goto error;
    }
    memcpy(out, output, out_len);

    rv = 0;

error:

    if (ctx)
        EVP_MAC_CTX_free(ctx);
    if (mac)
        EVP_MAC_free(mac);

    return rv;
}

int asft_crypto_generate_key(char *out, size_t out_len)
{
    unsigned char key[ASFT_KEY_LEN];
    int n;
    int rv = 1;

    if (out_len < ASFT_KEY_B64_LEN + 1)
        return 1;

    if (RAND_bytes(key, sizeof(key)) != 1)
        goto error;

    n = EVP_EncodeBlock((unsigned char *)out, key, sizeof(key));
    if (n != ASFT_KEY_B64_LEN)
        goto error;

    out[n] = '\0';
    rv = 0;

error:

    OPENSSL_cleanse(key, sizeof(key));

    return rv;
}

static int chaSIV_F(
    unsigned char *Ke,
    size_t Ke_len,
    unsigned char *K,
    unsigned char *N,
    size_t N_len
)
{
    return blake2s_mac(Ke, Ke_len, K, N, N_len, NULL, 0);
}

static int chaSIV_encrypt(
    void *cpkt,
    void *pkt,
    size_t pkt_len,
    void *K,
    void *N
) {
    int rv = -1;
    unsigned char *M = pkt + ASFT_TAG_LEN + ASFT_TS_XMIT;
    unsigned char *C = cpkt + ASFT_TAG_LEN + ASFT_TS_XMIT;
    size_t M_len = pkt_len - ASFT_TAG_LEN - ASFT_TS_XMIT;
    unsigned char *T = cpkt;
    size_t N_len = ASFT_TS_LEN;

    EVP_CIPHER_CTX *ctx = NULL;

    if (M_len < 1)
        goto error;

    if (chaSIV_H(T, K, N, N_len, M, M_len)) {
        asft_error("Encryption H() failed\n");
        goto error;
    }

    unsigned char E_nonce[CHACHA_CTR_SIZE] = {0};
    memcpy(E_nonce + 4, T, ASFT_TAG_LEN);

    unsigned char Ke[CHACHA_KEY_SIZE] = {0};
    if (chaSIV_F(Ke, CHACHA_KEY_SIZE, K, N, N_len)) {
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
    void *K,
    void *N
) {
    int rv = -1;
    unsigned char *M = pkt + ASFT_TAG_LEN + ASFT_TS_XMIT;
    unsigned char *C = cpkt + ASFT_TAG_LEN + ASFT_TS_XMIT;
    size_t C_len = cpkt_len - ASFT_TAG_LEN - ASFT_TS_XMIT;
    unsigned char *T = cpkt;
    size_t N_len = ASFT_TS_LEN;

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

    unsigned char Ke[CHACHA_KEY_SIZE] = {0};
    if (chaSIV_F(Ke, CHACHA_KEY_SIZE, K, N, N_len)) {
        asft_error("Decryption F() failed\n");
        goto error;
    }

    if (chacha20(M, C, C_len, Ke, E_nonce))
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

/*
 * Decode a base64 key of exactly ASFT_KEY_LEN bytes.
 * Returns 0 on success, 1 on any format error.
 */
int asft_crypto_key_decode(const char *b64, uint8_t out[ASFT_KEY_LEN])
{
    /* EVP_DecodeBlock writes up to 33 bytes for 44 characters and counts padding */
    uint8_t buf[ASFT_KEY_LEN + 1];
    size_t len;
    size_t pad = 0;
    int n;
    int rv = 1;

    if (!b64)
        return 1;

    len = strlen(b64);
    if (len != ASFT_KEY_B64_LEN)
        return 1;

    if (b64[len - 1] == '=')
        pad++;
    if (b64[len - 2] == '=')
        pad++;

    n = EVP_DecodeBlock(buf, (const unsigned char *)b64, (int)len);
    if (n < 0 || (size_t)n < pad || (size_t)n - pad != ASFT_KEY_LEN)
        goto error;

    memcpy(out, buf, ASFT_KEY_LEN);
    rv = 0;

error:

    OPENSSL_cleanse(buf, sizeof(buf));

    return rv;
}

int asft_crypto_key_valid(const char *b64)
{
    uint8_t key[ASFT_KEY_LEN];
    int rv = asft_crypto_key_decode(b64, key);

    OPENSSL_cleanse(key, sizeof(key));

    return rv;
}

struct asft_crypto_ctx *asft_crypto_ctx_init(const char *key_b64, const char *network_id_b64)
{
    struct asft_crypto_ctx *ctx;

    ctx = malloc(sizeof(*ctx));
    assert(ctx);
    memset(ctx, 0, sizeof(*ctx));

    /* peer key is the input keying material, network_id is the HKDF salt */
    uint8_t key[ASFT_KEY_LEN];
    uint8_t salt[ASFT_KEY_LEN];
    int rv = 1;

    if (asft_crypto_key_decode(key_b64, key))
        goto error;
    if (asft_crypto_key_decode(network_id_b64, salt))
        goto error;

    rv = HKDF(
        ctx->request_key, sizeof(ctx->request_key),
        key, sizeof(key),
        salt, sizeof(salt),
        "asft-request-key"
    );
    if (rv)
        goto error;

    rv = HKDF(
        ctx->response_key, sizeof(ctx->response_key),
        key, sizeof(key),
        salt, sizeof(salt),
        "asft-response-key"
    );
    if (rv)
        goto error;

    for (int dir = 0; dir < ASFT_MSG_DIR_COUNT; dir++) {
        rv = HKDF(
            ctx->msg_key[dir], sizeof(ctx->msg_key[dir]),
            key, sizeof(key),
            salt, sizeof(salt),
            msg_key_info[dir]
        );
        if (rv)
            goto error;

        rv = HKDF(
            ctx->msg_hdr_key[dir], sizeof(ctx->msg_hdr_key[dir]),
            key, sizeof(key),
            salt, sizeof(salt),
            msg_hdr_key_info[dir]
        );
        if (rv)
            goto error;
    }

    rv = 0;

error:

    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(salt, sizeof(salt));

    if (rv) {
        explicit_bzero(ctx, sizeof(*ctx));
        free(ctx);
        return NULL;
    }

    return ctx;
}

int asft_crypto_fingerprint(struct asft_crypto_ctx *ctx, char *out, size_t out_len)
{
    static const char hex[] = "0123456789abcdef";
    int rv = 1;
    EVP_MD *md = NULL;
    EVP_MD_CTX *mdctx = NULL;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;

    if (!ctx || !out || out_len < ASFT_FINGERPRINT_HEX_LEN + 1)
        return 1;

    md = EVP_MD_fetch(NULL, "BLAKE2B-512", NULL);
    if (!md) {
        asft_error("Fingerprint digest is not supported\n");
        goto error;
    }

    mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        asft_error("Cannot create fingerprint digest context\n");
        goto error;
    }

    if (EVP_DigestInit_ex2(mdctx, md, NULL) != 1 ||
        EVP_DigestUpdate(mdctx, ctx->request_key, sizeof(ctx->request_key)) != 1 ||
        EVP_DigestUpdate(mdctx, ctx->response_key, sizeof(ctx->response_key)) != 1 ||
        EVP_DigestUpdate(mdctx, ctx->msg_key, sizeof(ctx->msg_key)) != 1 ||
        EVP_DigestUpdate(mdctx, ctx->msg_hdr_key, sizeof(ctx->msg_hdr_key)) != 1 ||
        EVP_DigestFinal_ex(mdctx, digest, &digest_len) != 1) {
        asft_error("Cannot compute fingerprint\n");
        goto error;
    }

    if (digest_len < ASFT_FINGERPRINT_LEN) {
        asft_error("Fingerprint digest is too short\n");
        goto error;
    }

    for (size_t i = 0; i < ASFT_FINGERPRINT_LEN; i++) {
        out[i * 2] = hex[digest[i] >> 4];
        out[i * 2 + 1] = hex[digest[i] & 0x0f];
    }
    out[ASFT_FINGERPRINT_HEX_LEN] = '\0';

    rv = 0;

error:

    if (mdctx)
        EVP_MD_CTX_free(mdctx);
    if (md)
        EVP_MD_free(md);

    OPENSSL_cleanse(digest, sizeof(digest));

    if (rv)
        out[0] = '\0';

    return rv;
}

void asft_crypto_timestamp_init(struct asft_crypto_ctx *ctx)
{
    ctx->timestamp = asft_timestamp();
}

void asft_crypto_set_session_timestamp(struct asft_crypto_ctx *ctx)
{
    if (ctx) {
        ctx->session_timestamp = ctx->timestamp;
    }
}

int asft_encrypt_req(
    struct asft_crypto_ctx *ctx,
    asft_pkt *cpkt,
    asft_pkt *pkt,
    size_t pkt_len
) {
    int rv = 1;

    union ts t;
    uint64_t now = asft_timestamp();

    /* Timestamps are nonces and replay marks: a packet needs a strictly newer
     * one than the previous packet to this peer. When the round trip is faster
     * than one timestamp step, wait for the next step. If the clock went
     * backwards (now < ctx->timestamp), do not wait; the receiver will report
     * a replay. */
    while (now == ctx->timestamp) {
        usleep(100);
        now = asft_timestamp();
    }

    ctx->timestamp = now;
    t.be = htobe64(ctx->timestamp);

    rv = chaSIV_encrypt(cpkt, pkt, pkt_len, ctx->request_key, t.bytes);
    if (rv)
        goto error;

    memcpy(cpkt->timestamp, &t.bytes[ASFT_TS_HIDE], ASFT_TS_XMIT);

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
    int64_t now = asft_timestamp();
    union ts t;
    t.be = htobe64(now);
    memcpy(&t.bytes[ASFT_TS_HIDE], cpkt->timestamp, ASFT_TS_XMIT);
    int64_t received = be64toh(t.be);
    int64_t diff = now - received;
    int64_t diff_max = 1ULL << (ASFT_TS_XMIT * 8 - 1);

    int64_t correction = 0;
    if (diff > diff_max)
        correction = 1;
    else if (diff < -diff_max)
        correction = -1;

    int64_t corrected = received + correction * (1ULL << (ASFT_TS_XMIT * 8));
    t.be = htobe64(corrected);

    int rv = chaSIV_decrypt(pkt, cpkt, cpkt_len, ctx->request_key, t.bytes);
    if (rv)
        return 1;

    uint64_t timestamp_new = be64toh(t.be);

    if (timestamp_new <= ctx->timestamp) {
        asft_error("Replay detected\n");
        return 1;
    }

    ctx->timestamp = timestamp_new;

    return 0;
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

    rv = chaSIV_encrypt(cpkt, pkt, pkt_len, ctx->response_key, t.bytes);
    if (rv)
        goto error;

    // Timestamp field in response is unused
    // Fill with current time to make it look similar to request
    union ts t_fake;
    t_fake.be = htobe64(asft_timestamp());
    memcpy(cpkt->timestamp, &t_fake.bytes[ASFT_TS_HIDE], ASFT_TS_XMIT);

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

    union ts t;
    t.be = htobe64(ctx->timestamp);

    rv = chaSIV_decrypt(pkt, cpkt, cpkt_len, ctx->response_key, t.bytes);
    if (rv)
        goto error;

    rv = 0;

error:

    return rv;
}

int asft_sign_msg(
    struct asft_crypto_ctx *ctx,
    enum asft_msg_dir dir,
    void *mac,
    size_t mac_len,
    void *msg,
    size_t msg_len
) {
    union ts session_ts;
    session_ts.be = htobe64(ctx->session_timestamp);

    if (blake2s_mac(mac, mac_len, ctx->msg_key[dir], msg, msg_len, session_ts.bytes, ASFT_TS_LEN)) {
        asft_error("Message MAC calculation failed\n");
        return 1;
    }

    return 0;
}

int asft_verify_msg(
    struct asft_crypto_ctx *ctx,
    enum asft_msg_dir dir,
    void *mac,
    size_t mac_len,
    void *msg,
    size_t msg_len
) {
    unsigned char actual_mac[CHACHA_KEY_SIZE];
    union ts session_ts;
    session_ts.be = htobe64(ctx->session_timestamp);

    if (blake2s_mac(actual_mac, mac_len, ctx->msg_key[dir], msg, msg_len, session_ts.bytes, ASFT_TS_LEN)) {
        asft_error("Message actual MAC calculation failed\n");
        return 1;
    }

    if (CRYPTO_memcmp(actual_mac, mac, mac_len))
        return 1;

    return 0;
}

int asft_sign_msg_hdr(
    struct asft_crypto_ctx *ctx,
    enum asft_msg_dir dir,
    void *mac,
    size_t mac_len,
    void *msg_hdr,
    size_t msg_hdr_len
) {
    union ts session_ts;
    session_ts.be = htobe64(ctx->session_timestamp);

    if (blake2s_mac(mac, mac_len, ctx->msg_hdr_key[dir], msg_hdr, msg_hdr_len, session_ts.bytes, ASFT_TS_LEN)) {
        asft_error("Message header MAC calculation failed\n");
        return 1;
    }

    return 0;
}

int asft_verify_msg_hdr(
    struct asft_crypto_ctx *ctx,
    enum asft_msg_dir dir,
    void *mac,
    size_t mac_len,
    void *msg_hdr,
    size_t msg_hdr_len
) {
    unsigned char actual_mac[CHACHA_KEY_SIZE];
    union ts session_ts;
    session_ts.be = htobe64(ctx->session_timestamp);

    if (blake2s_mac(actual_mac, mac_len, ctx->msg_hdr_key[dir], msg_hdr, msg_hdr_len, session_ts.bytes, ASFT_TS_LEN)) {
        asft_error("Message header actual MAC calculation failed\n");
        return 1;
    }

    if (CRYPTO_memcmp(actual_mac, mac, mac_len))
        return 1;

    return 0;
}
