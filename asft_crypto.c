#define _GNU_SOURCE

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/rand.h>
#include <stdbool.h>

#include "asft.h"

#define CHACHA_KEY_SIZE 32
#define CHACHA_IV_SIZE  16

/*
 * OpenSSL's ChaCha20 IV is 128 bits: a 64-bit little-endian block counter
 * followed by a 64-bit nonce. Our nonce therefore cannot be longer than
 * 8 bytes, and it starts at byte 8 of the IV.
 */
#define CHACHA_NONCE_SIZE 8
#define CHACHA_NONCE_OFFSET 8

/* The packet counter is the only nonce byte (inside the ChaCha20 64-bit nonce) */
#define COUNTER_MAX      255

#define SESSION_KEY_SIZE 32

/*
 * Number of session keys the node keeps as candidates until an authenticated
 * data packet proves which one the gateway is using (see candidate_key and
 * asft_decrypt_req()). A replayed key exchange request makes the node answer
 * with a fresh key pair and push another candidate into this ring, so enough
 * replays could evict the real key before the gateway's first data packet.
 *
 * Ten is sufficient for the intended channel: the candidate only has to
 * survive from the node's response to that first data packet, i.e. one
 * turnaround plus one frame. On a half-duplex serial link an attacker sharing
 * the medium cannot inject while either endpoint is transmitting without
 * corrupting the frame, so only one or two packets fit in that window, far
 * fewer than needed to overwrite ten candidates. At 1200 baud a full frame
 * already takes about 720 ms.
 *
 * Revisit this bound if the deployment uses a buffered/high-latency modem,
 * gives an attacker a high-speed local path to the node, or allows an active
 * jammer to stretch the window across the gateway's retries. The fix in those
 * cases is a small replay cache of request xnonces (or a rate limit), not a
 * larger ring. Even if candidates are churned, no session key is disclosed:
 * each response uses a fresh X448 key pair.
 */
#define KEX_CANDIDATES   10

struct asft_crypto_ctx {
    /*
     * Packet counter, 1..COUNTER_MAX, used as the nonce. Gateway: counter of
     * the last request sent. Node: counter of the last request accepted.
     * 0 means no packet yet in this session.
     */
    uint8_t counter;
    uint8_t msg_key[ASFT_MSG_DIR_COUNT][CHACHA_KEY_SIZE];
    uint8_t msg_hdr_key[ASFT_MSG_DIR_COUNT][CHACHA_KEY_SIZE];
    uint8_t kex_key[ASFT_MSG_DIR_COUNT][CHACHA_KEY_SIZE];

    /*
     * Session key (gateway: established). On the node, new keys are written
     * to candidate_key as key exchange requests arrive, a ring buffer that
     * overwrites the oldest entry, until a packet confirms one of them.
     */
    bool session_valid;
    uint8_t session_key[SESSION_KEY_SIZE];
    uint8_t pkt_enc_key[ASFT_MSG_DIR_COUNT][CHACHA_KEY_SIZE];
    uint8_t pkt_mac_key[ASFT_MSG_DIR_COUNT][CHACHA_KEY_SIZE];
    /* Wire representation of the counter: keyed permutation of byte values and its inverse */
    uint8_t ctr_fwd[ASFT_MSG_DIR_COUNT][256];
    uint8_t ctr_inv[ASFT_MSG_DIR_COUNT][256];
    uint8_t candidate_key[KEX_CANDIDATES][SESSION_KEY_SIZE];
    size_t candidate_idx;
    size_t candidate_cnt;

    /* Gateway: key exchange request waiting for its response */
    EVP_PKEY *kex_pkey;
    uint8_t kex_pub[ASFT_X448_KEY_LEN];
    uint8_t kex_xnonce[ASFT_KEY_XNONCE_LEN];
};

static const char *const msg_key_info[ASFT_MSG_DIR_COUNT] = {
    "asft-message-key-request",
    "asft-message-key-response",
};

static const char *const msg_hdr_key_info[ASFT_MSG_DIR_COUNT] = {
    "asft-message-header-key-request",
    "asft-message-header-key-response",
};

static const char *const kex_key_info[ASFT_MSG_DIR_COUNT] = {
    "asft-key-exchange-request",
    "asft-key-exchange-response",
};

static const char *const pkt_enc_info[ASFT_MSG_DIR_COUNT] = {
    "asft-packet-encryption-key-request",
    "asft-packet-encryption-key-response",
};

static const char *const pkt_mac_info[ASFT_MSG_DIR_COUNT] = {
    "asft-packet-mac-key-request",
    "asft-packet-mac-key-response",
};

static const char *const ctr_perm_info[ASFT_MSG_DIR_COUNT] = {
    "asft-counter-permutation-request",
    "asft-counter-permutation-response",
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

/*
 * Build a ChaCha20 IV with the packet counter in the nonce area. The 64-bit
 * block counter stays zero and OpenSSL advances it for every 64-byte block.
 * The counter goes into the rightmost byte of the 128-bit IV.
 */
static void chacha20_iv_counter(unsigned char iv[CHACHA_IV_SIZE], uint8_t counter)
{
    iv[CHACHA_IV_SIZE - 1] = counter;
}

/* Build a ChaCha20 IV from an 8-byte nonce. */
static void chacha20_iv_nonce(unsigned char iv[CHACHA_IV_SIZE], const uint8_t nonce[CHACHA_NONCE_SIZE])
{
    memcpy(iv + CHACHA_NONCE_OFFSET, nonce, CHACHA_NONCE_SIZE);
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
    size_t output_len = 0;
    unsigned char output[CHACHA_KEY_SIZE] = {0};

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

    if (EVP_MAC_final(ctx, output, &output_len, CHACHA_KEY_SIZE) != 1) {
        asft_error("Cannot finalize MAC\n");
        goto error;
    }
    memcpy(out, output, out_len);

    rv = 0;

error:

    OPENSSL_cleanse(output, sizeof(output));

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
    if (!ctx)
        return NULL;
    memset(ctx, 0, sizeof(*ctx));

    /* peer key is the input keying material, network_id is the HKDF salt */
    uint8_t key[ASFT_KEY_LEN];
    uint8_t salt[ASFT_KEY_LEN];
    int rv = 1;

    if (asft_crypto_key_decode(key_b64, key))
        goto error;
    if (asft_crypto_key_decode(network_id_b64, salt))
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

        rv = HKDF(
            ctx->kex_key[dir], sizeof(ctx->kex_key[dir]),
            key, sizeof(key),
            salt, sizeof(salt),
            kex_key_info[dir]
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
        EVP_DigestUpdate(mdctx, ctx->kex_key, sizeof(ctx->kex_key)) != 1 ||
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

static int derive_pkt_key(uint8_t out[CHACHA_KEY_SIZE], const uint8_t key[SESSION_KEY_SIZE], const char *info)
{
    static char salt[] = "asft-session";

    return HKDF(out, CHACHA_KEY_SIZE, (void *) key, SESSION_KEY_SIZE, salt, sizeof(salt) - 1, info);
}

/*
 * Keyed permutation of the byte values (Fisher-Yates shuffle driven by HKDF
 * output) and its inverse. The counter is sent as fwd[counter] so that the
 * sequence of counters is not visible on the line.
 */
static int derive_ctr_perm(
    uint8_t fwd[256],
    uint8_t inv[256],
    const uint8_t key[SESSION_KEY_SIZE],
    const char *info
) {
    static char salt[] = "asft-session";
    uint8_t rnd[2 * 255];
    int rv = 1;

    if (HKDF(rnd, sizeof(rnd), (void *) key, SESSION_KEY_SIZE, salt, sizeof(salt) - 1, info))
        goto error;

    for (int i = 0; i < 256; i++)
        fwd[i] = i;

    for (int i = 255; i > 0; i--) {
        const uint8_t *r = &rnd[2 * (255 - i)];
        int j = ((r[0] << 8) | r[1]) % (i + 1);
        uint8_t t = fwd[i];

        fwd[i] = fwd[j];
        fwd[j] = t;
    }

    for (int i = 0; i < 256; i++)
        inv[fwd[i]] = i;

    rv = 0;

error:

    OPENSSL_cleanse(rnd, sizeof(rnd));

    return rv;
}

/* Make key the session key: derive the packet keys and restart the counter. */
static int session_set(struct asft_crypto_ctx *ctx, const uint8_t key[SESSION_KEY_SIZE])
{
    uint8_t enc[ASFT_MSG_DIR_COUNT][CHACHA_KEY_SIZE] = {0};
    uint8_t mac[ASFT_MSG_DIR_COUNT][CHACHA_KEY_SIZE] = {0};
    uint8_t fwd[ASFT_MSG_DIR_COUNT][256] = {0};
    uint8_t inv[ASFT_MSG_DIR_COUNT][256] = {0};
    int rv = 1;

    for (int dir = 0; dir < ASFT_MSG_DIR_COUNT; dir++) {
        if (derive_pkt_key(enc[dir], key, pkt_enc_info[dir]) ||
            derive_pkt_key(mac[dir], key, pkt_mac_info[dir]) ||
            derive_ctr_perm(fwd[dir], inv[dir], key, ctr_perm_info[dir]))
            goto error;
    }

    memcpy(ctx->session_key, key, SESSION_KEY_SIZE);
    memcpy(ctx->pkt_enc_key, enc, sizeof(enc));
    memcpy(ctx->pkt_mac_key, mac, sizeof(mac));
    memcpy(ctx->ctr_fwd, fwd, sizeof(fwd));
    memcpy(ctx->ctr_inv, inv, sizeof(inv));
    ctx->counter = 0;
    ctx->session_valid = true;

    rv = 0;

error:

    OPENSSL_cleanse(enc, sizeof(enc));
    OPENSSL_cleanse(mac, sizeof(mac));
    OPENSSL_cleanse(fwd, sizeof(fwd));
    OPENSSL_cleanse(inv, sizeof(inv));

    return rv;
}

bool asft_crypto_session_exhausted(struct asft_crypto_ctx *ctx)
{
    return ctx->counter >= COUNTER_MAX;
}

/*
 * Packet protection: encrypt-then-MAC.
 *
 * Wire layout is tag | wire counter | flags | data, where the wire counter is
 * the counter passed through a keyed permutation (see derive_ctr_perm), with
 * a different permutation for each direction. flags and data are encrypted
 * with ChaCha20 (nonce = real counter, in the rightmost byte of the IV;
 * the 64-bit block counter stays zero), then the tag is the BLAKE2s-MAC over
 * counter and the ciphertext, truncated to ASFT_TAG_LEN. Keys are per session
 * and per direction. A response reuses the counter of the request it answers.
 */

#define PKT_BODY_OFFSET offsetof(asft_pkt, flags)

static int pkt_seal(
    struct asft_crypto_ctx *ctx,
    enum asft_msg_dir dir,
    asft_pkt *cpkt,
    asft_pkt *pkt,
    size_t pkt_len
) {
    unsigned char iv[CHACHA_IV_SIZE] = {0};

    if (!ctx->session_valid || pkt_len <= PKT_BODY_OFFSET)
        return 1;

    cpkt->counter = ctx->ctr_fwd[dir][ctx->counter];
    chacha20_iv_counter(iv, ctx->counter);

    if (chacha20(&cpkt->flags, &pkt->flags, pkt_len - PKT_BODY_OFFSET, ctx->pkt_enc_key[dir], iv))
        return 1;

    if (blake2s_mac(cpkt->tag, ASFT_TAG_LEN, ctx->pkt_mac_key[dir],
                    &cpkt->counter, pkt_len - ASFT_TAG_LEN, NULL, 0))
        return 1;

    return 0;
}

static int pkt_verify(uint8_t *mac_key, asft_pkt *cpkt, size_t cpkt_len)
{
    unsigned char tag[CHACHA_KEY_SIZE];

    if (cpkt_len <= PKT_BODY_OFFSET)
        return 1;

    if (blake2s_mac(tag, ASFT_TAG_LEN, mac_key, &cpkt->counter, cpkt_len - ASFT_TAG_LEN, NULL, 0))
        return 1;

    return CRYPTO_memcmp(tag, cpkt->tag, ASFT_TAG_LEN) != 0;
}

/* Packet must be verified first */
static int pkt_decrypt(
    struct asft_crypto_ctx *ctx,
    enum asft_msg_dir dir,
    asft_pkt *pkt,
    asft_pkt *cpkt,
    size_t cpkt_len,
    uint8_t counter
) {
    unsigned char iv[CHACHA_IV_SIZE] = {0};

    chacha20_iv_counter(iv, counter);

    return chacha20(&pkt->flags, &cpkt->flags, cpkt_len - PKT_BODY_OFFSET, ctx->pkt_enc_key[dir], iv);
}

int asft_encrypt_req(
    struct asft_crypto_ctx *ctx,
    asft_pkt *cpkt,
    asft_pkt *pkt,
    size_t pkt_len
) {
    /* The gateway starts a new session before the counter runs out */
    if (!ctx->session_valid || asft_crypto_session_exhausted(ctx))
        return 1;

    ctx->counter++;

    return pkt_seal(ctx, ASFT_MSG_DIR_REQUEST, cpkt, pkt, pkt_len);
}

int asft_decrypt_req(
    struct asft_crypto_ctx *ctx,
    asft_pkt *pkt,
    asft_pkt *cpkt,
    size_t cpkt_len
) {
    bool verified = ctx->session_valid &&
        !pkt_verify(ctx->pkt_mac_key[ASFT_MSG_DIR_REQUEST], cpkt, cpkt_len);

    /* Otherwise the packet may be the first one under a candidate key, newest first */
    for (size_t k = 0; !verified && k < ctx->candidate_cnt; k++) {
        size_t i = (ctx->candidate_idx + KEX_CANDIDATES - 1 - k) % KEX_CANDIDATES;
        uint8_t mac_key[CHACHA_KEY_SIZE] = {0};
        int rv = derive_pkt_key(mac_key, ctx->candidate_key[i], pkt_mac_info[ASFT_MSG_DIR_REQUEST]);

        if (!rv)
            rv = pkt_verify(mac_key, cpkt, cpkt_len);
        OPENSSL_cleanse(mac_key, sizeof(mac_key));
        if (rv)
            continue;

        if (session_set(ctx, ctx->candidate_key[i]))
            return 1;
        asft_debug("Session key established\n");
        OPENSSL_cleanse(ctx->candidate_key, sizeof(ctx->candidate_key));
        ctx->candidate_idx = 0;
        ctx->candidate_cnt = 0;
        verified = true;
    }

    if (!verified)
        return 1;

    uint8_t counter = ctx->ctr_inv[ASFT_MSG_DIR_REQUEST][cpkt->counter];

    if (counter <= ctx->counter) {
        asft_error("Replay detected\n");
        return 1;
    }

    if (pkt_decrypt(ctx, ASFT_MSG_DIR_REQUEST, pkt, cpkt, cpkt_len, counter))
        return 1;

    ctx->counter = counter;

    return 0;
}

int asft_encrypt_resp(
    struct asft_crypto_ctx *ctx,
    asft_pkt *cpkt,
    asft_pkt *pkt,
    size_t pkt_len
) {
    return pkt_seal(ctx, ASFT_MSG_DIR_RESPONSE, cpkt, pkt, pkt_len);
}

int asft_decrypt_resp(
    struct asft_crypto_ctx *ctx,
    asft_pkt *pkt,
    asft_pkt *cpkt,
    size_t cpkt_len
) {
    if (!ctx->session_valid || cpkt_len <= PKT_BODY_OFFSET)
        return 1;

    /* Verify before comparing the counter, so nothing about the session's
     * counter permutation is exposed to unauthenticated packets. */
    if (pkt_verify(ctx->pkt_mac_key[ASFT_MSG_DIR_RESPONSE], cpkt, cpkt_len))
        return 1;

    /* Only a response to the last request is acceptable */
    if (cpkt->counter != ctx->ctr_fwd[ASFT_MSG_DIR_RESPONSE][ctx->counter])
        return 1;

    return pkt_decrypt(ctx, ASFT_MSG_DIR_RESPONSE, pkt, cpkt, cpkt_len, ctx->counter);
}

int asft_sign_msg(
    struct asft_crypto_ctx *ctx,
    enum asft_msg_dir dir,
    void *mac,
    size_t mac_len,
    void *msg,
    size_t msg_len
) {
    if (blake2s_mac(mac, mac_len, ctx->msg_key[dir], msg, msg_len, NULL, 0)) {
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
    if (blake2s_mac(actual_mac, mac_len, ctx->msg_key[dir], msg, msg_len, NULL, 0)) {
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
    if (blake2s_mac(mac, mac_len, ctx->msg_hdr_key[dir], msg_hdr, msg_hdr_len, NULL, 0)) {
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
    if (blake2s_mac(actual_mac, mac_len, ctx->msg_hdr_key[dir], msg_hdr, msg_hdr_len, NULL, 0)) {
        asft_error("Message header actual MAC calculation failed\n");
        return 1;
    }

    if (CRYPTO_memcmp(actual_mac, mac, mac_len))
        return 1;

    return 0;
}

/*
 * Session key exchange.
 *
 * Both packets carry a fresh 128-bit random xnonce and an ephemeral X448
 * public key (the rest of the packet is zero padding). They are protected
 * with encrypt-then-MAC: HKDF over the per-direction key exchange key
 * (derived from the peer key) salted with the xnonce yields the 64-bit
 * ChaCha20 nonce, the 256-bit ChaCha20 subkey, and the BLAKE2s-MAC key, so
 * only a holder of the peer key can build or read them. The response MAC
 * also covers the request public key, binding it to the request.
 *
 * The session key is HKDF over the X448 shared secret, salted with both
 * xnonces and public keys.
 */

#define KEX_ENC_LEN (ASFT_X448_KEY_LEN + ASFT_KEY_PKT_PAD)

static int kex_packet_keys(
    uint8_t nonce[CHACHA_NONCE_SIZE],
    uint8_t subkey[CHACHA_KEY_SIZE],
    uint8_t mac_key[CHACHA_KEY_SIZE],
    struct asft_crypto_ctx *ctx,
    enum asft_msg_dir dir,
    const uint8_t xnonce[ASFT_KEY_XNONCE_LEN]
) {
    uint8_t keys[CHACHA_NONCE_SIZE + 2 * CHACHA_KEY_SIZE] = {0};
    int rv = 1;

    if (HKDF(keys, sizeof(keys), ctx->kex_key[dir], CHACHA_KEY_SIZE,
             (void *) xnonce, ASFT_KEY_XNONCE_LEN, "asft-key-exchange-packet"))
        goto error;

    memcpy(nonce, keys, CHACHA_NONCE_SIZE);
    memcpy(subkey, keys + CHACHA_NONCE_SIZE, CHACHA_KEY_SIZE);
    memcpy(mac_key, keys + CHACHA_NONCE_SIZE + CHACHA_KEY_SIZE, CHACHA_KEY_SIZE);

    rv = 0;

error:

    OPENSSL_cleanse(keys, sizeof(keys));

    return rv;
}

static int kex_seal(
    struct asft_crypto_ctx *ctx,
    enum asft_msg_dir dir,
    asft_key_pkt *pkt,
    const uint8_t pub[ASFT_X448_KEY_LEN],
    uint8_t *ad,
    size_t ad_len
) {
    int rv = 1;
    uint8_t nonce[CHACHA_NONCE_SIZE] = {0}, subkey[CHACHA_KEY_SIZE] = {0};
    uint8_t mac_key[CHACHA_KEY_SIZE] = {0};
    uint8_t iv[CHACHA_IV_SIZE] = {0};
    uint8_t plain[KEX_ENC_LEN] = {0};

    memcpy(plain, pub, ASFT_X448_KEY_LEN);

    if (RAND_bytes(pkt->xnonce, sizeof(pkt->xnonce)) != 1)
        goto error;
    if (kex_packet_keys(nonce, subkey, mac_key, ctx, dir, pkt->xnonce))
        goto error;
    chacha20_iv_nonce(iv, nonce);
    if (chacha20(pkt->X448_pubkey, plain, sizeof(plain), subkey, iv))
        goto error;
    if (blake2s_mac(pkt->tag, sizeof(pkt->tag), mac_key,
                    pkt->xnonce, sizeof(pkt->xnonce) + KEX_ENC_LEN,
                    ad, ad_len))
        goto error;

    rv = 0;

error:

    OPENSSL_cleanse(nonce, sizeof(nonce));
    OPENSSL_cleanse(subkey, sizeof(subkey));
    OPENSSL_cleanse(mac_key, sizeof(mac_key));
    OPENSSL_cleanse(plain, sizeof(plain));

    return rv;
}

/* Returns 1 if the packet does not authenticate, -1 on internal error. */
static int kex_open(
    struct asft_crypto_ctx *ctx,
    enum asft_msg_dir dir,
    uint8_t pub[ASFT_X448_KEY_LEN],
    const asft_key_pkt *pkt,
    uint8_t *ad,
    size_t ad_len
) {
    int rv = -1;
    uint8_t nonce[CHACHA_NONCE_SIZE] = {0}, subkey[CHACHA_KEY_SIZE] = {0};
    uint8_t mac_key[CHACHA_KEY_SIZE] = {0};
    uint8_t iv[CHACHA_IV_SIZE] = {0};
    uint8_t tag[ASFT_KEY_TAG_LEN] = {0};

    if (kex_packet_keys(nonce, subkey, mac_key, ctx, dir, pkt->xnonce))
        goto error;
    if (blake2s_mac(tag, sizeof(tag), mac_key,
                    (uint8_t *) pkt->xnonce, sizeof(pkt->xnonce) + KEX_ENC_LEN,
                    ad, ad_len))
        goto error;

    if (CRYPTO_memcmp(tag, pkt->tag, sizeof(tag))) {
        rv = 1;
        goto error;
    }

    chacha20_iv_nonce(iv, nonce);
    if (chacha20(pub, (uint8_t *) pkt->X448_pubkey, ASFT_X448_KEY_LEN, subkey, iv))
        goto error;

    rv = 0;

error:

    OPENSSL_cleanse(nonce, sizeof(nonce));
    OPENSSL_cleanse(subkey, sizeof(subkey));
    OPENSSL_cleanse(mac_key, sizeof(mac_key));
    OPENSSL_cleanse(tag, sizeof(tag));

    return rv;
}

static EVP_PKEY *kex_keygen(uint8_t pub[ASFT_X448_KEY_LEN])
{
    size_t len = ASFT_X448_KEY_LEN;
    EVP_PKEY *pkey = EVP_PKEY_Q_keygen(NULL, NULL, "X448");

    if (!pkey)
        return NULL;

    if (EVP_PKEY_get_raw_public_key(pkey, pub, &len) != 1 || len != ASFT_X448_KEY_LEN) {
        EVP_PKEY_free(pkey);
        return NULL;
    }

    return pkey;
}

/* Derive the session key from our private key and the other side's public key. */
static int kex_derive_session_key(
    uint8_t out[SESSION_KEY_SIZE],
    EVP_PKEY *pkey,
    const uint8_t peer_pub[ASFT_X448_KEY_LEN],
    const uint8_t *req_xnonce,
    const uint8_t *req_pub,
    const uint8_t *resp_xnonce,
    const uint8_t *resp_pub
) {
    int rv = 1;
    EVP_PKEY *peer = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    uint8_t shared[ASFT_X448_KEY_LEN] = {0};
    size_t shared_len = sizeof(shared);
    uint8_t transcript[2 * (ASFT_KEY_XNONCE_LEN + ASFT_X448_KEY_LEN)];
    uint8_t *t = transcript;

    peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X448, NULL, peer_pub, ASFT_X448_KEY_LEN);
    if (!peer)
        goto error;

    pctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!pctx)
        goto error;

    /* Fails for low-order peer points (all-zero shared secret) */
    if (EVP_PKEY_derive_init(pctx) != 1 ||
        EVP_PKEY_derive_set_peer(pctx, peer) != 1 ||
        EVP_PKEY_derive(pctx, shared, &shared_len) != 1 ||
        shared_len != sizeof(shared))
        goto error;

    memcpy(t, req_xnonce, ASFT_KEY_XNONCE_LEN);   t += ASFT_KEY_XNONCE_LEN;
    memcpy(t, req_pub, ASFT_X448_KEY_LEN);        t += ASFT_X448_KEY_LEN;
    memcpy(t, resp_xnonce, ASFT_KEY_XNONCE_LEN);  t += ASFT_KEY_XNONCE_LEN;
    memcpy(t, resp_pub, ASFT_X448_KEY_LEN);

    if (HKDF(out, SESSION_KEY_SIZE, shared, sizeof(shared),
             transcript, sizeof(transcript), "asft-session-key"))
        goto error;

    rv = 0;

error:

    OPENSSL_cleanse(shared, sizeof(shared));
    if (pctx)
        EVP_PKEY_CTX_free(pctx);
    if (peer)
        EVP_PKEY_free(peer);

    return rv;
}

/* Log a hash of the session key, so that both ends can be compared without exposing the key */
static void debug_dump_key_hash(const uint8_t key[SESSION_KEY_SIZE], char *desc)
{
    uint8_t hash[32] = {0};

    if (EVP_Q_digest(NULL, "BLAKE2S-256", NULL, key, SESSION_KEY_SIZE, hash, NULL) != 1) {
        asft_error("Cannot hash session key\n");
        goto error;
    }

    asft_debug_dump(hash, sizeof(hash), desc);

error:

    OPENSSL_cleanse(hash, sizeof(hash));
}

static void kex_clear_pending(struct asft_crypto_ctx *ctx)
{
    if (ctx->kex_pkey)
        EVP_PKEY_free(ctx->kex_pkey);
    ctx->kex_pkey = NULL;
}

void asft_crypto_ctx_free(struct asft_crypto_ctx *ctx)
{
    if (!ctx)
        return;

    /* Free the pending X448 private key, then wipe all derived keys */
    kex_clear_pending(ctx);
    OPENSSL_cleanse(ctx, sizeof(*ctx));
    free(ctx);
}

int asft_crypto_kex_request(struct asft_crypto_ctx *ctx, asft_key_pkt *req)
{
    uint8_t pub[ASFT_X448_KEY_LEN];
    EVP_PKEY *pkey;

    kex_clear_pending(ctx);

    pkey = kex_keygen(pub);
    if (!pkey) {
        asft_error("Cannot generate X448 key\n");
        return 1;
    }

    if (kex_seal(ctx, ASFT_MSG_DIR_REQUEST, req, pub, NULL, 0)) {
        asft_error("Cannot build key exchange request\n");
        EVP_PKEY_free(pkey);
        return 1;
    }

    ctx->kex_pkey = pkey;
    memcpy(ctx->kex_pub, pub, sizeof(pub));
    memcpy(ctx->kex_xnonce, req->xnonce, sizeof(ctx->kex_xnonce));

    return 0;
}

int asft_crypto_kex_accept(struct asft_crypto_ctx *ctx, const asft_key_pkt *resp)
{
    uint8_t resp_pub[ASFT_X448_KEY_LEN] = {0};
    uint8_t key[SESSION_KEY_SIZE] = {0};
    int rv = 1;

    if (!ctx->kex_pkey)
        goto error;

    /* The response is bound to our request through its public key */
    if (kex_open(ctx, ASFT_MSG_DIR_RESPONSE, resp_pub, resp, ctx->kex_pub, sizeof(ctx->kex_pub)))
        goto error;

    if (kex_derive_session_key(key, ctx->kex_pkey, resp_pub,
                               ctx->kex_xnonce, ctx->kex_pub,
                               resp->xnonce, resp_pub)) {
        asft_error("Cannot derive session key\n");
        goto error;
    }

    debug_dump_key_hash(key, "Session key hash (gateway)");
    if (session_set(ctx, key)) {
        asft_error("Cannot set session key\n");
        goto error;
    }

    kex_clear_pending(ctx);
    rv = 0;

error:

    OPENSSL_cleanse(key, sizeof(key));

    return rv;
}

int asft_crypto_kex_respond(struct asft_crypto_ctx *ctx, asft_key_pkt *resp, const asft_key_pkt *req)
{
    uint8_t req_pub[ASFT_X448_KEY_LEN] = {0};
    uint8_t pub[ASFT_X448_KEY_LEN] = {0};
    uint8_t key[SESSION_KEY_SIZE] = {0};
    EVP_PKEY *pkey = NULL;
    int rv;

    rv = kex_open(ctx, ASFT_MSG_DIR_REQUEST, req_pub, req, NULL, 0);
    if (rv)
        goto error;

    rv = -1;

    pkey = kex_keygen(pub);
    if (!pkey) {
        asft_error("Cannot generate X448 key\n");
        goto error;
    }

    if (kex_seal(ctx, ASFT_MSG_DIR_RESPONSE, resp, pub, req_pub, sizeof(req_pub))) {
        asft_error("Cannot build key exchange response\n");
        goto error;
    }

    if (kex_derive_session_key(key, pkey, req_pub,
                               req->xnonce, req_pub,
                               resp->xnonce, pub)) {
        asft_error("Cannot derive session key\n");
        goto error;
    }

    debug_dump_key_hash(key, "Session key hash (node)");

    /* Kept as a candidate until the gateway proves it holds the same key; oldest entry is overwritten */
    memcpy(ctx->candidate_key[ctx->candidate_idx], key, sizeof(key));
    ctx->candidate_idx = (ctx->candidate_idx + 1) % KEX_CANDIDATES;
    if (ctx->candidate_cnt < KEX_CANDIDATES)
        ctx->candidate_cnt++;

    rv = 0;

error:

    OPENSSL_cleanse(key, sizeof(key));
    if (pkey)
        EVP_PKEY_free(pkey);

    return rv;
}
