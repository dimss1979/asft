#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif /*_GNU_SOURCE*/

#include <stdio.h>
#include <string.h>
#include <endian.h>
#include <stdlib.h>
#include <stdbool.h>
#include <time.h>

#include "asft_proto.h"
#include "asft_crypto.h"
#include "asft_serial.h"
#include "asft_misc.h"
#include "asft_file.h"

#include "asft_node.h"

static struct gateway
{
    char *label;
    struct asft_crypto_ctx *crypto_ctx;

    struct asft_msg_tx msg_tx;
    struct asft_msg_rx msg_rx;
    char *upload_dir;
    char *download_dir;
} gw = { 0 };

static int gateway_init()
{
    if (!gw.label) {
        asft_error("Gateway not specified\n");
        goto error;
    }
    if (asprintf(&gw.upload_dir, "to_%s", gw.label) < 0)
        goto error;
    if (asprintf(&gw.download_dir, "from_%s", gw.label) < 0)
        goto error;

    if (!gw.crypto_ctx)
        goto error;

    return 0;

error:

    return -1;
}

static void process_req_data(asft_pkt *req, asft_pkt *resp, size_t *resp_len, bool have_data)
{
    if (have_data) {
        asft_msg_rx_receive(&gw.msg_rx, be16toh(req->data.block_idx), req->data.data, gw.download_dir);
    }
    uint8_t ack = req->b.ack;
    asft_msg_tx_ack(&gw.msg_tx, ack);
    asft_msg_tx_init(&gw.msg_tx, gw.upload_dir);

    if (gw.msg_tx.msg) {
        *resp_len = sizeof(resp->data);

        uint16_t block_idx = 0;
        asft_msg_tx_send(&gw.msg_tx, &block_idx, resp->data.data);
        resp->data.block_idx = htobe16(block_idx);
    } else {
        *resp_len = sizeof(resp->nodata);
    }
    asft_msg_rx_get_ack(&gw.msg_rx, &resp->b.ack);
}

int asft_node_loop()
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
        if (!rv || !cpkt || !pkt_len) {
            continue;
        }

        asft_debug("Received %u bytes\n", pkt_len);

        rv = asft_decrypt_req(gw.crypto_ctx, &pkt, cpkt, pkt_len);
        if (rv) {
            asft_debug("Decryption failed\n");
            continue;
        }

        switch (pkt_len)
        {
            case ASFT_PKT_LEN_NODATA:
                process_req_data(&pkt, &resp, &resp_len, false);
                break;
            case ASFT_PKT_LEN_DATA:
                process_req_data(&pkt, &resp, &resp_len, true);
                break;
            default:
                asft_error("Unknown request length %u bytes\n", pkt_len);
        }

        if (resp_len) {
            if (asft_encrypt_resp(gw.crypto_ctx, &cresp, &resp, resp_len)) {
                asft_error("Response encryption failed\n");
                return 1;
            }

            asft_debug("Sending response %u bytes\n", resp_len);

            if (asft_serial_send((unsigned char*) &cresp, resp_len) < 0) {
                asft_error("Cannot send response\n");
                return 1;
            }
        }
    }
}

int asft_node_set_gateway(char *label, char *password)
{
    if (strchr(label, '/')) {
        asft_error("Invalid label - contains slash\n");
        goto error;
    }

    free(gw.label);

    gw.label = strdup(label);
    gw.crypto_ctx = asft_crypto_ctx_init(password);
    gw.msg_tx.crypto_ctx = gw.crypto_ctx;
    gw.msg_rx.crypto_ctx = gw.crypto_ctx;

    if (!gw.crypto_ctx || !gw.label)
        goto error;

    return 0;

error:

    free(gw.label);
    gw.label = NULL;

    return -1;
}
