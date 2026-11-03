#ifndef _ASFT_H_
#define _ASFT_H_

#include <stddef.h>
#include <stdint.h>
#include <time.h>

/* proto */

/*
 * Per-packet tag and per-message MAC lengths.
 *
 * The packet tag is deliberately short to limit per-packet overhead on
 * severely constrained links; it bounds single-packet forgery and is also
 * used as the ChaCha20 SIV nonce, so packets sharing a timestamp must not
 * produce colliding tags.
 *
 * The file header and body MACs are sent once per file, so they are longer
 * and provide the end-to-end integrity guarantee independently of the
 * short per-packet tag.
 */
#define ASFT_TAG_LEN     5
#define ASFT_MSG_MAC_LEN 8
#define ASFT_TS_LEN      sizeof(uint64_t)
#define ASFT_TS_XMIT    2
#define ASFT_TS_HIDE    (ASFT_TS_LEN - ASFT_TS_XMIT)
#define ASFT_BLOCK_LEN  100

typedef struct _asft_pkt {
    uint8_t tag[ASFT_TAG_LEN];
    uint8_t timestamp[ASFT_TS_XMIT];
    uint8_t flags;
    uint8_t data[ASFT_BLOCK_LEN];
} __attribute__((packed)) asft_pkt;

struct asft_pkt_flags {
    uint8_t rst;
    uint8_t seq;
    uint8_t ack;
};

static inline void asft_pkt_flags_decode(struct asft_pkt_flags *o, uint8_t i)
{
    o->rst = (i >> 2) & 1;
    o->seq = (i >> 1) & 1;
    o->ack = (i >> 0) & 1;
}

static inline uint8_t asft_pkt_flags_encode(struct asft_pkt_flags *i)
{
    return
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
void asft_set_timestamp_step(uint64_t step);
uint64_t asft_now(void);
uint64_t asft_timestamp(void);
uint64_t asft_timestamp_to_ms(uint64_t timestamp);

/* time sync */

int asft_timesync_set_socket(char *path);
int asft_timesync_enabled(void);
void asft_timesync_sample(uint64_t timestamp_ms, const struct timespec *rx_time);

/* serial */

int asft_serial_init(char *devname, char *baudrate_string, size_t pkt_len_max);
int asft_serial_send(unsigned char *buf, size_t len);
int asft_serial_receive(unsigned char **buf_ptr, size_t *len_ptr);
void asft_serial_set_packet_loss(double probability);
void asft_serial_rx_time(struct timespec *ts);

/* crypto */

/* Short fingerprint over all four derived encryption keys, used by -c. */
#define ASFT_FINGERPRINT_LEN     8
#define ASFT_FINGERPRINT_HEX_LEN (ASFT_FINGERPRINT_LEN * 2)

struct asft_crypto_ctx;

struct asft_crypto_ctx *asft_crypto_ctx_init(char *password, char *network_id);
int asft_crypto_fingerprint(struct asft_crypto_ctx *ctx, char *out, size_t out_len);
void asft_crypto_timestamp_init(struct asft_crypto_ctx *ctx);
uint64_t asft_crypto_last_rx_timestamp(struct asft_crypto_ctx *ctx);

void asft_crypto_set_session_timestamp(struct asft_crypto_ctx *ctx);

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
    void *mac,
    size_t mac_len,
    void *msg,
    size_t msg_len
);

int asft_verify_msg(
    struct asft_crypto_ctx *ctx,
    void *mac,
    size_t mac_len,
    void *msg,
    size_t msg_len
);

int asft_sign_msg_hdr(
    struct asft_crypto_ctx *ctx,
    void *mac,
    size_t mac_len,
    void *msg_hdr,
    size_t msg_hdr_len
);

int asft_verify_msg_hdr(
    struct asft_crypto_ctx *ctx,
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
};

struct asft_msg_rx {
    uint8_t *msg;
    size_t msg_len;
    size_t msg_pos;
    uint8_t ack;
    void *crypto_ctx;
};

void asft_msg_tx_init(struct asft_msg_tx *tx, char *dir);
void asft_msg_tx_send(struct asft_msg_tx *tx, uint8_t *pkt_seq, uint8_t *pkt_data);
void asft_msg_tx_ack(struct asft_msg_tx *tx, uint8_t ack);
void asft_msg_tx_cancel(struct asft_msg_tx *tx);

int asft_msg_rx_receive(struct asft_msg_rx *rx, uint8_t pkt_seq, uint8_t *pkt_data, char *dir);
void asft_msg_rx_get_ack(struct asft_msg_rx *rx, uint8_t *ack);
void asft_msg_rx_cancel(struct asft_msg_rx *rx);

/* node */

int asft_node_loop(void);
int asft_node_set_gateway(char *label, char *password);
int asft_node_init_crypto(char *network_id);
int asft_node_print_peers(void);

/* gateway */

int asft_gateway_loop(void);
int asft_gateway_add_node(char *label, char *password);
int asft_gateway_init_crypto(char *network_id);
int asft_gateway_print_peers(void);
void asft_gateway_set_retry_timeout(int new_timeout);
void asft_gateway_set_backoff_time_max(uint32_t new_backoff_time_max);

#endif /* _ASFT_H_ */
