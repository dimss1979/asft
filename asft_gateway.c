#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif /*_GNU_SOURCE*/

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <endian.h>
#include <sys/random.h>
#include <stdbool.h>
#include <stdlib.h>
#include <time.h>

#include "asft.h"

static struct asft_peer *peer_first = NULL;
static unsigned int peer_cnt = 0;

static int retry_timeout = 5;
static uint32_t backoff_time_max = 60;

static void apply_backoff(struct asft_peer *n)
{
    if (n->backoff_time == 0) {
        n->backoff_time = 1;
    } else {
        n->backoff_time *= 2;
        if (n->backoff_time > backoff_time_max) {
            n->backoff_time = backoff_time_max;
        }
    }
    n->pause_until = asft_now() + n->backoff_time * 1000;
}

static void apply_error_backoff(struct asft_peer *n)
{
    n->backoff_time = backoff_time_max / 2;
    n->pause_until = asft_now() + n->backoff_time * 1000;
}

static void reset_backoff(struct asft_peer *n)
{
    n->backoff_time = 0;
    n->pause_until = 0;
}

static void unpause_for_download()
{
    uint64_t now = asft_now();
    struct asft_peer *n = peer_first;

    while (n)
    {
        if (n->pause_until > now && !n->msg_tx.msg && n->ready) {
            asft_msg_tx_init(&n->msg_tx, n->download_dir);
            if (n->msg_tx.msg) {
                reset_backoff(n);
            }
        }

        n = n->next;
    }
}

static struct asft_peer *node_pick_next(struct asft_peer *cur)
{
    struct asft_peer *n = NULL;
    uint64_t now = asft_now();

    if (cur)
        n = cur->next;

    for (unsigned int i = 0; i < peer_cnt; i++) {
        if (!n)
            n = peer_first;

        if (n->pause_until <= now) {
            return n;
        }

        n = n->next;
    }

    return NULL;
}

static int nodes_init(void)
{
    struct asft_peer *n;

    if (!peer_cnt) {
        asft_error("No nodes configured\n");
        goto error;
    }

    n = peer_first;
    while (n) {
        if (asprintf(&n->upload_dir, "from_%s", n->label) < 0)
            goto error;
        if (asprintf(&n->download_dir, "to_%s", n->label) < 0)
            goto error;

        n->msg_tx.crypto_ctx = n->crypto_ctx;
        n->msg_rx.crypto_ctx = n->crypto_ctx;
        n->msg_tx.dir = ASFT_MSG_DIR_REQUEST;
        n->msg_rx.dir = ASFT_MSG_DIR_RESPONSE;

        n = n->next;
    }

    return 0;

error:

    return -1;
}

int asft_gateway_init_crypto(char *network_id)
{
    struct asft_peer *n = peer_first;

    if (!peer_cnt) {
        asft_error("No nodes configured\n");
        return -1;
    }

    while (n) {
        n->crypto_ctx = asft_crypto_ctx_init(n->key, network_id);
        if (!n->crypto_ctx)
            return -1;

        asft_peer_clear_key(n);

        n = n->next;
    }

    return 0;
}

int asft_gateway_print_peers(void)
{
    char fingerprint[ASFT_FINGERPRINT_HEX_LEN + 1];
    struct asft_peer *n = peer_first;
    int rv = 0;

    while (n) {
        if (asft_crypto_fingerprint(n->crypto_ctx, fingerprint, sizeof(fingerprint))) {
            asft_error("Cannot compute fingerprint for peer '%s'\n", n->label);
            rv = -1;
        } else {
            asft_info("%s %s\n", fingerprint, n->label);
        }

        n = n->next;
    }

    return rv;
}

/* Returns true if a local error occurred while processing the data packet. */
static bool process_resp_data(struct asft_peer *n, asft_pkt *resp, struct asft_pkt_flags *resp_flags, bool have_data)
{
    if (have_data) {
        if (asft_msg_rx_receive(&n->msg_rx, resp_flags->seq, resp->data, n->upload_dir)) {
            asft_error("Error while processing data packet from '%s'\n", n->label);

            asft_msg_tx_cancel(&n->msg_tx);
            asft_msg_rx_cancel(&n->msg_rx);
            n->ready = false;
            return true;
        }
    }

    asft_msg_tx_ack(&n->msg_tx, resp_flags->ack);
    asft_msg_tx_init(&n->msg_tx, n->download_dir);

    return false;
}

int asft_gateway_loop(void)
{
    int rv;
    struct asft_peer *n = NULL;
    uint64_t timeout;

    if (nodes_init()) {
        asft_error("Initialization failed\n");
        return 1;
    }

    while(1)
    {
        unpause_for_download();
        n = node_pick_next(n);

        if (!n) {
            sleep(1);
            continue;
        }

        asft_debug("Picked node '%s'\n", n->label);

        asft_pkt pkt = {0}, cpkt = {0}, resp = {0};
        asft_pkt *cresp = NULL;
        size_t pkt_len = 0, rx_packet_len = 0;
        bool keep_talking = false;
        struct asft_pkt_flags req_flags = {0};

        if (n->ready) {
            asft_msg_tx_init(&n->msg_tx, n->download_dir);
            if (n->msg_tx.msg) {
                pkt_len = sizeof(asft_pkt);

                asft_msg_tx_send(&n->msg_tx, &req_flags.seq, pkt.data);
                keep_talking = true;
            } else {
                pkt_len = sizeof(asft_pkt) - ASFT_BLOCK_LEN;
            }
            asft_msg_rx_get_ack(&n->msg_rx, &req_flags.ack);
        } else {
            asft_debug("Sending reset to '%s'\n", n->label);
            pkt_len = sizeof(asft_pkt) - ASFT_BLOCK_LEN;
            req_flags.rst = 1;
            keep_talking = true;
        }

        pkt.flags = asft_pkt_flags_encode(&req_flags);

        rv = asft_encrypt_req(n->crypto_ctx, &cpkt, &pkt, pkt_len);
        if (rv) {
            asft_error("Node '%s' cannot encrypt packet\n", n->label);
            return 1;
        }

        asft_debug("Sending request %u bytes\n", pkt_len);

        rv = asft_serial_send((unsigned char*) &cpkt, pkt_len);
        if (rv < 0) {
            asft_error("Cannot send request\n");
            return 1;
        }

        bool got_response = false;
        bool error_seen = false;
        timeout = asft_now() + retry_timeout * 1000;
        while(timeout > asft_now() && !got_response) {
            rv = asft_serial_receive((unsigned char**) &cresp, &rx_packet_len);
            if (rv < 0) {
                asft_error("Cannot receive response\n");
                return 1;
            }

            if (
                !cresp ||
                rx_packet_len < (sizeof(asft_pkt) - ASFT_BLOCK_LEN) ||
                rx_packet_len > sizeof(asft_pkt)
            )
                continue;

            asft_debug("Received %u bytes\n", rx_packet_len);

            if (asft_decrypt_resp(n->crypto_ctx, &resp, cresp, rx_packet_len)) {
                asft_debug("Decryption failed\n");
                continue;
            }

            struct asft_pkt_flags resp_flags;
            asft_pkt_flags_decode(&resp_flags, resp.flags);
            got_response = true;

            if (resp_flags.err) {
                asft_debug("Node '%s' reported receive error\n", n->label);
                error_seen = true;
            }

            if (resp_flags.rst) {
                asft_debug("Node '%s' is not ready\n", n->label);
                asft_msg_tx_cancel(&n->msg_tx);
                asft_msg_rx_cancel(&n->msg_rx);
                n->ready = false;
                keep_talking = true;
            } else if (!n->ready) {
                asft_debug("Node '%s' is ready\n", n->label);
                asft_crypto_set_session_timestamp(n->crypto_ctx);
                asft_msg_tx_cancel(&n->msg_tx);
                asft_msg_rx_cancel(&n->msg_rx);
                n->ready = true;
            } else if (rx_packet_len == (sizeof(asft_pkt) - ASFT_BLOCK_LEN)) {
                if (process_resp_data(n, &resp, &resp_flags, false))
                    error_seen = true;
            } else {
                if (process_resp_data(n, &resp, &resp_flags, true))
                    error_seen = true;
                keep_talking = true;
            }
        };

        if (!got_response)
            asft_debug("No response\n");

        if (error_seen) {
            apply_error_backoff(n);
        } else if (!keep_talking || !got_response) {
            apply_backoff(n);
        } else {
            reset_backoff(n);
        }
    }

    return 0;
}

int asft_gateway_add_node(char *label, char *key)
{
    struct asft_peer *new = NULL;

    new = malloc(sizeof(*new));
    if (!new)
        goto error;
    memset(new, 0, sizeof(*new));

    if (asft_peer_set_label_key(new, label, key))
        goto error;

    new->next = peer_first;
    peer_first = new;
    peer_cnt++;

    return 0;

error:

    if (new) {
        free(new->label);
        free(new);
    }

    return -1;
}

void asft_gateway_set_retry_timeout(int new_timeout)
{
    retry_timeout = new_timeout;
}

void asft_gateway_set_backoff_time_max(uint32_t new_backoff_time_max)
{
    backoff_time_max = new_backoff_time_max;
}
