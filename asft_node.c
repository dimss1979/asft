#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif /*_GNU_SOURCE*/

#include <stdio.h>
#include <string.h>
#include <endian.h>
#include <stdlib.h>
#include <stdbool.h>
#include <time.h>

#include "asft.h"

static struct gateway
{
    char *label;
    char *key;
    struct asft_crypto_ctx *crypto_ctx;

    bool ready;

    struct asft_msg_tx msg_tx;
    struct asft_msg_rx msg_rx;
    char *upload_dir;
    char *download_dir;
} gw = { 0 };

static int gateway_init(void)
{
    if (!gw.label) {
        asft_error("Gateway not specified\n");
        goto error;
    }
    if (!gw.crypto_ctx) {
        asft_error("Gateway crypto context not initialized\n");
        goto error;
    }
    if (asprintf(&gw.upload_dir, "to_%s", gw.label) < 0)
        goto error;
    if (asprintf(&gw.download_dir, "from_%s", gw.label) < 0)
        goto error;

    gw.msg_tx.crypto_ctx = gw.crypto_ctx;
    gw.msg_rx.crypto_ctx = gw.crypto_ctx;

    return 0;

error:

    return -1;
}

int asft_node_init_crypto(char *network_id)
{
    if (!gw.label) {
        asft_error("Gateway not specified\n");
        return -1;
    }
    if (!gw.key) {
        asft_error("Gateway key not specified\n");
        return -1;
    }

    gw.crypto_ctx = asft_crypto_ctx_init(gw.key, network_id);
    if (!gw.crypto_ctx)
        return -1;

    asft_crypto_timestamp_init(gw.crypto_ctx);

    explicit_bzero(gw.key, strlen(gw.key));
    free(gw.key);
    gw.key = NULL;

    return 0;
}

int asft_node_print_peers(void)
{
    char fingerprint[ASFT_FINGERPRINT_HEX_LEN + 1];

    if (asft_crypto_fingerprint(gw.crypto_ctx, fingerprint, sizeof(fingerprint))) {
        asft_error("Cannot compute fingerprint for peer '%s'\n", gw.label);
        return 1;
    }

    asft_info("%s %s\n", fingerprint, gw.label);

    return 0;
}

static void process_req_data(asft_pkt *req, struct asft_pkt_flags *req_flags, asft_pkt *resp, size_t *resp_len, struct asft_pkt_flags *resp_flags, bool have_data)
{
    if (!gw.ready) {
        asft_debug("Not ready\n");
        *resp_len = sizeof(asft_pkt) - ASFT_BLOCK_LEN;
        resp_flags->rst = 1;
        return;
    }

    if (have_data) {
        if (asft_msg_rx_receive(&gw.msg_rx, req_flags->seq, req->data, gw.download_dir)) {
            asft_error("Error while processing data packet\n");

            asft_msg_tx_cancel(&gw.msg_tx);
            asft_msg_rx_cancel(&gw.msg_rx);
            gw.ready = false;
            *resp_len = sizeof(asft_pkt) - ASFT_BLOCK_LEN;
            resp_flags->rst = 1;
            return;
        }
    }

    asft_msg_tx_ack(&gw.msg_tx, req_flags->ack);
    asft_msg_tx_init(&gw.msg_tx, gw.upload_dir);

    if (gw.msg_tx.msg) {
        *resp_len = sizeof(asft_pkt);

        asft_msg_tx_send(&gw.msg_tx, &resp_flags->seq, resp->data);
    } else {
        *resp_len = sizeof(asft_pkt) - ASFT_BLOCK_LEN;
    }
    asft_msg_rx_get_ack(&gw.msg_rx, &resp_flags->ack);
}

int asft_node_loop(void)
{
    if (gateway_init()) {
        asft_error("Initialization failed\n");
        return 1;
    }

    while (1) {
        int rv = 0;
        asft_pkt pkt = {0}, resp = {0}, cresp = {0};
        asft_pkt *cpkt = NULL;
        size_t pkt_len = 0, resp_len = 0;

        rv = asft_serial_receive((unsigned char**) &cpkt, &pkt_len);
        if (rv < 0) {
            asft_error("Cannot receive packet\n");
            return 1;
        }
        if (!rv || !cpkt || pkt_len < (sizeof(asft_pkt) - ASFT_BLOCK_LEN) || pkt_len > sizeof(asft_pkt)) {
            continue;
        }

        asft_debug("Received %u bytes\n", pkt_len);

        rv = asft_decrypt_req(gw.crypto_ctx, &pkt, cpkt, pkt_len);
        if (rv) {
            asft_debug("Decryption failed\n");
            continue;
        }

        if (pkt_len == sizeof(asft_pkt) - ASFT_BLOCK_LEN) {
            struct timespec rx_time;

            asft_serial_rx_time(&rx_time);
            asft_timesync_sample(
                asft_timestamp_to_ms(asft_crypto_last_rx_timestamp(gw.crypto_ctx)),
                &rx_time
            );
        }

        struct asft_pkt_flags resp_flags = {0}, req_flags;
        asft_pkt_flags_decode(&req_flags, pkt.flags);

        if (req_flags.rst) {
            asft_debug("Reset requested\n");
            asft_msg_tx_cancel(&gw.msg_tx);
            asft_msg_rx_cancel(&gw.msg_rx);
            asft_crypto_set_session_timestamp(gw.crypto_ctx);
            gw.ready = true;
            resp_len = sizeof(asft_pkt) - ASFT_BLOCK_LEN;
        } else if (pkt_len == sizeof(asft_pkt) - ASFT_BLOCK_LEN) {
            process_req_data(&pkt, &req_flags, &resp, &resp_len, &resp_flags, false);
        } else {
            process_req_data(&pkt, &req_flags, &resp, &resp_len, &resp_flags, true);
        }

        if (resp_len) {
            resp.flags = asft_pkt_flags_encode(&resp_flags);

            if (asft_encrypt_resp(gw.crypto_ctx, &cresp, &resp, resp_len)) {
                asft_error("Response encryption failed\n");
                return 1;
            }

            asft_debug("Sending response %u bytes\n", resp_len);

            if (asft_serial_send((unsigned char*) &cresp, resp_len) < 0) {
                asft_error("Cannot send response\n");
                return 1;
            }
        } else {
            asft_error("No response. Invalid request?\n");
        }
    }
}

int asft_node_set_gateway(char *label, char *key)
{
    if (strchr(label, '/')) {
        asft_error("Invalid label - contains slash\n");
        goto error;
    }

    char *new_label = strdup(label);
    char *new_key = strdup(key);
    if (!new_label || !new_key) {
        free(new_label);
        if (new_key) {
            explicit_bzero(new_key, strlen(new_key));
            free(new_key);
        }
        goto error;
    }

    free(gw.label);
    if (gw.key) {
        explicit_bzero(gw.key, strlen(gw.key));
        free(gw.key);
    }

    gw.label = new_label;
    gw.key = new_key;

    return 0;

error:

    return -1;
}
