#ifndef _ASFT_H_
#define _ASFT_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* proto */

/*
 * Per-packet tag and per-message MAC lengths.
 *
 * The packet tag is deliberately short to limit per-packet overhead on
 * severely constrained links; it bounds single-packet forgery.
 *
 * The file header and body MACs are sent once per file, so they are longer
 * and provide the end-to-end integrity guarantee independently of the
 * short per-packet tag.
 */
#define ASFT_TAG_LEN     6
#define ASFT_MSG_MAC_LEN 8
#define ASFT_BLOCK_LEN  100

typedef struct _asft_pkt {
    uint8_t tag[ASFT_TAG_LEN];
    uint8_t counter; /* obfuscated nonce, see asft_crypto.c */
    uint8_t flags;
    uint8_t data[ASFT_BLOCK_LEN];
} __attribute__((packed)) asft_pkt;

/*
 * Key exchange packet, the same length as a full data packet so that it
 * cannot be told apart by size. Everything after xnonce is encrypted.
 * tag is a MAC over xnonce and the ciphertext (plus the request public key
 * for the response). The 128-bit xnonce and the per-direction key exchange
 * key are expanded with HKDF into the ChaCha20 nonce, ChaCha20 subkey, and
 * MAC key.
 */
#define ASFT_KEY_TAG_LEN    16
#define ASFT_KEY_XNONCE_LEN 16
#define ASFT_X448_KEY_LEN   56
#define ASFT_KEY_PKT_PAD \
    (sizeof(asft_pkt) - ASFT_KEY_TAG_LEN - ASFT_KEY_XNONCE_LEN - ASFT_X448_KEY_LEN)

typedef struct _asft_key_pkt {
    uint8_t tag[ASFT_KEY_TAG_LEN];
    uint8_t xnonce[ASFT_KEY_XNONCE_LEN];
    uint8_t X448_pubkey[ASFT_X448_KEY_LEN];
    uint8_t pad[ASFT_KEY_PKT_PAD];
} __attribute__((packed)) asft_key_pkt;

_Static_assert(sizeof(asft_key_pkt) == sizeof(asft_pkt), "key packet must match data packet length");

struct asft_pkt_flags {
    uint8_t rst;
    uint8_t seq;
    uint8_t ack;
    uint8_t err;
};

static inline void asft_pkt_flags_decode(struct asft_pkt_flags *o, uint8_t i)
{
    o->err = (i >> 3) & 1;
    o->rst = (i >> 2) & 1;
    o->seq = (i >> 1) & 1;
    o->ack = (i >> 0) & 1;
}

static inline uint8_t asft_pkt_flags_encode(struct asft_pkt_flags *i)
{
    return
        ((i->err & 1) << 3) |
        ((i->rst & 1) << 2) |
        ((i->seq & 1) << 1) |
        ((i->ack & 1) << 0);
}

/* misc */

void asft_error(const char *format, ...);
void asft_info(const char *format, ...);
void asft_debug(const char *format, ...);
void asft_dump(void *buf, size_t len, char *desc);
void asft_debug_dump(void *buf, size_t len, char *desc);
void asft_set_debug(unsigned int d);
uint64_t asft_now(void);

/* serial */

int asft_serial_init(char *devname, char *baudrate_string, size_t pkt_len_max);
int asft_serial_send(unsigned char *buf, size_t len);
int asft_serial_receive(unsigned char **buf_ptr, size_t *len_ptr);
void asft_serial_set_packet_loss(double probability);

/* crypto */

/*
 * Direction of a message, i.e. the packet type that carries it. Each
 * direction has its own message keys, so a message cannot be reflected
 * into the other direction.
 */
enum asft_msg_dir {
    ASFT_MSG_DIR_REQUEST = 0,   /* gateway -> node, carried in requests */
    ASFT_MSG_DIR_RESPONSE = 1,  /* node -> gateway, carried in responses */
    ASFT_MSG_DIR_COUNT
};

/* Short fingerprint over all derived link keys, used by -c. */
#define ASFT_FINGERPRINT_LEN     8
#define ASFT_FINGERPRINT_HEX_LEN (ASFT_FINGERPRINT_LEN * 2)

/* Raw key size and its base64 length without the terminator. */
#define ASFT_KEY_LEN     32
#define ASFT_KEY_B64_LEN 44

int asft_crypto_generate_key(char *out, size_t out_len);
int asft_crypto_key_decode(const char *b64, uint8_t out[ASFT_KEY_LEN]);
int asft_crypto_key_valid(const char *b64);

struct asft_crypto_ctx;

struct asft_crypto_ctx *asft_crypto_ctx_init(const char *key_b64, const char *network_id_b64);
void asft_crypto_ctx_free(struct asft_crypto_ctx *ctx);
int asft_crypto_fingerprint(struct asft_crypto_ctx *ctx, char *out, size_t out_len);

/* Gateway: true when the packet counter is used up and a new session key is needed. */
bool asft_crypto_session_exhausted(struct asft_crypto_ctx *ctx);

/*
 * Session key exchange (X448). Gateway builds a request, node answers it and
 * the gateway then accepts the response. Return 0 on success, 1 when the
 * packet does not authenticate, -1 on internal error (node respond only).
 */

/* Gateway: start a new exchange, replacing any pending one. */
int asft_crypto_kex_request(struct asft_crypto_ctx *ctx, asft_key_pkt *req);
/* Gateway: verify the response to the pending request and set the session key. */
int asft_crypto_kex_accept(struct asft_crypto_ctx *ctx, const asft_key_pkt *resp);
/*
 * Node: verify a request and build the response. The derived session key is
 * only stored as a candidate; nothing else changes.
 */
int asft_crypto_kex_respond(struct asft_crypto_ctx *ctx, asft_key_pkt *resp, const asft_key_pkt *req);

int asft_encrypt_req(
    struct asft_crypto_ctx *ctx,
    asft_pkt *cpkt,
    asft_pkt *pkt,
    size_t pkt_len
);

int asft_decrypt_req(
    struct asft_crypto_ctx *ctx,
    asft_pkt *pkt,
    asft_pkt *cpkt,
    size_t cpkt_len
);

int asft_encrypt_resp(
    struct asft_crypto_ctx *ctx,
    asft_pkt *cpkt,
    asft_pkt *pkt,
    size_t pkt_len
);

int asft_decrypt_resp(
    struct asft_crypto_ctx *ctx,
    asft_pkt *pkt,
    asft_pkt *cpkt,
    size_t cpkt_len
);

int asft_sign_msg(
    struct asft_crypto_ctx *ctx,
    enum asft_msg_dir dir,
    void *mac,
    size_t mac_len,
    void *msg,
    size_t msg_len
);

int asft_verify_msg(
    struct asft_crypto_ctx *ctx,
    enum asft_msg_dir dir,
    void *mac,
    size_t mac_len,
    void *msg,
    size_t msg_len
);

int asft_sign_msg_hdr(
    struct asft_crypto_ctx *ctx,
    enum asft_msg_dir dir,
    void *mac,
    size_t mac_len,
    void *msg_hdr,
    size_t msg_hdr_len
);

int asft_verify_msg_hdr(
    struct asft_crypto_ctx *ctx,
    enum asft_msg_dir dir,
    void *mac,
    size_t mac_len,
    void *msg_hdr,
    size_t msg_hdr_len
);

/* file */

struct asft_msg_tx {
    uint8_t *msg;
    char *path;
    size_t msg_len;
    size_t msg_pos;
    uint8_t seq;
    void *crypto_ctx;
    enum asft_msg_dir dir;
};

struct asft_msg_rx {
    uint8_t *msg;
    size_t msg_len;
    size_t msg_pos;
    uint8_t ack;
    void *crypto_ctx;
    enum asft_msg_dir dir;
};

void asft_msg_tx_init(struct asft_msg_tx *tx, char *dir);
void asft_msg_tx_send(struct asft_msg_tx *tx, uint8_t *pkt_seq, uint8_t *pkt_data);
void asft_msg_tx_ack(struct asft_msg_tx *tx, uint8_t ack);
void asft_msg_tx_cancel(struct asft_msg_tx *tx);

int asft_msg_rx_receive(struct asft_msg_rx *rx, uint8_t pkt_seq, uint8_t *pkt_data, char *dir);
void asft_msg_rx_get_ack(struct asft_msg_rx *rx, uint8_t *ack);
void asft_msg_rx_cancel(struct asft_msg_rx *rx);

/* peer */

/*
 * State of a remote peer, shared by node and gateway modes. A node keeps a
 * single peer (its gateway); a gateway keeps a linked list of peer nodes.
 * Fields only used in gateway mode are marked as such.
 */
struct asft_peer {
    struct asft_peer *next;             /* gateway: peer list */
    char *label;
    char key[ASFT_KEY_B64_LEN + 1];
    struct asft_crypto_ctx *crypto_ctx;

    uint64_t pause_until;               /* gateway */
    uint32_t backoff_time;              /* gateway */
    uint64_t no_response_count;         /* gateway */

    // Note that these two flags are generally independent of each other
    // Because file transfer can outlive session key
    bool ready; // File transfer protocol ready
    bool session_key_established; // Session key established with this peer

    struct asft_msg_tx msg_tx;
    struct asft_msg_rx msg_rx;
    char *upload_dir;
    char *download_dir;
};

int asft_peer_set_label_key(struct asft_peer *peer, const char *label, const char *key);
void asft_peer_clear_key(struct asft_peer *peer);

/* node */

int asft_node_loop(void);
int asft_node_set_gateway(char *label, char *key);
int asft_node_init_crypto(char *network_id);
void asft_node_deinit_crypto(void);
int asft_node_print_peers(void);

/* gateway */

int asft_gateway_loop(void);
int asft_gateway_add_node(char *label, char *key);
int asft_gateway_init_crypto(char *network_id);
void asft_gateway_deinit_crypto(void);
int asft_gateway_print_peers(void);
void asft_gateway_set_retry_timeout(int new_timeout);
void asft_gateway_set_backoff_time_max(uint32_t new_backoff_time_max);

#endif /* _ASFT_H_ */
