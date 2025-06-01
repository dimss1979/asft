#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif /*_GNU_SOURCE*/

#include <stdio.h>
#include <string.h>
#include <sys/random.h>
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
    char *password;
    struct asft_crypto_ctx *crypto_ctx;

    struct asft_key ikey_req;
    struct asft_key ikey_resp;
    struct asft_key skey_req;
    struct asft_key skey_resp;
    struct asft_ecdh *ecdh;
    bool have_skey;

    uint16_t last_packet_number;
    uint32_t last_ecdh_timestamp;

    struct asft_blob_tx blob_tx;
    struct asft_blob_rx blob_rx;
    char *upload_dir;
    char *download_dir;
} gw = { 0 };

static int gateway_init()
{
    if (!gw.label || !gw.password) {
        asft_error("Gateway not specified\n");
        goto error;
    }
    if(asft_kdf(&gw.ikey_req, gw.password, strlen(gw.password), asft_crypto_init_key_req)) {
        asft_error("Gateway initial key derivation failed\n");
        goto error;
    }
    if(asft_kdf(&gw.ikey_resp, gw.password, strlen(gw.password), asft_crypto_init_key_resp)) {
        asft_error("Gateway initial key derivation failed\n");
        goto error;
    }
    if (asprintf(&gw.upload_dir, "to_%s", gw.label) < 0)
        goto error;
    if (asprintf(&gw.download_dir, "from_%s", gw.label) < 0)
        goto error;

    gw.crypto_ctx = asft_crypto_ctx_init(gw.label);
    if (!gw.crypto_ctx)
        goto error;

    return 0;

error:

    return -1;
}

static void process_req_ecdh(asft_pkt *req, asft_pkt *resp, size_t *resp_len)
{
    uint32_t now = (uint32_t) time(NULL);
    uint32_t rx_timestamp = be32toh(req->b.nonce);
    if (rx_timestamp <= gw.last_ecdh_timestamp) {
        asft_error("Timestamp %u too small, last was %u\n", rx_timestamp, gw.last_ecdh_timestamp);
        return;
    }
    if (llabs((int64_t) rx_timestamp - now) > ASFT_TS_TOLERANCE) {
        asft_error("Timestamp %u out of tolerance, now it's %u\n", rx_timestamp, now);
        return;
    }
    gw.last_ecdh_timestamp = rx_timestamp;

    if (asft_ecdh_prepare(&gw.ecdh, resp->ecdh.public_key))
        goto error;

    if (asft_ecdh_process(&gw.ecdh, req->ecdh.public_key, &gw.skey_req, &gw.skey_resp))
        goto error;

    gw.have_skey = true;
    gw.last_packet_number = 0;

    *resp_len = sizeof(resp->ecdh);
    resp->b.nonce = htobe32(rx_timestamp);

    asft_info("Session key exchange complete\n");

    return;

error:

    asft_error("Session key exchange failed\n");

    return;
}

static void process_req_data(asft_pkt *req, asft_pkt *resp, size_t *resp_len, bool have_data)
{
    uint16_t rx_packet_number = be32toh(req->b.nonce);

    if (rx_packet_number <= gw.last_packet_number) {
        asft_error("Packet number %u too small, last was %u\n", rx_packet_number, gw.last_packet_number);
        return;
    }
    if ((rx_packet_number - gw.last_packet_number) > ASFT_MAX_RETRIES) {
        asft_error("Packet number %u too big, last was %u\n", rx_packet_number, gw.last_packet_number);
        return;
    }
    gw.last_packet_number = rx_packet_number;

    if (have_data) {
        asft_blob_rx_receive(&gw.blob_rx, be16toh(req->data.block_idx), req->data.data, gw.download_dir);
    }
    uint8_t ack = req->b.ack;
    asft_blob_tx_ack(&gw.blob_tx, ack);
    asft_blob_tx_init(&gw.blob_tx, gw.upload_dir);

    if (gw.blob_tx.blob) {
        *resp_len = sizeof(resp->data);

        uint16_t block_idx = 0;
        asft_blob_tx_send(&gw.blob_tx, &block_idx, resp->data.data);
        resp->data.block_idx = htobe16(block_idx);
    } else {
        *resp_len = sizeof(resp->nodata);
    }
    asft_blob_rx_get_ack(&gw.blob_rx, &resp->b.ack);
    resp->b.nonce = htobe32(rx_packet_number);
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

        rv = 1;
        if (gw.have_skey && pkt_len != ASFT_PKT_LEN_ECDH) {
            rv = asft_chaSIV_decrypt(&pkt, cpkt, pkt_len, &gw.skey_req, sizeof(pkt.b.nonce));
        } else if (pkt_len == ASFT_PKT_LEN_ECDH) {
            rv = asft_chaSIV_decrypt(&pkt, cpkt, pkt_len, &gw.ikey_req, sizeof(pkt.b.nonce));
        }
        if (rv) {
            asft_debug("Decryption failed\n");
            continue;
        }

        size_t resp_nonce_len = sizeof(pkt.b.nonce);
        struct asft_key *key_resp = &gw.skey_resp;
        switch (pkt_len)
        {
            case ASFT_PKT_LEN_ECDH:
                process_req_ecdh(&pkt, &resp, &resp_len);
                key_resp = &gw.ikey_resp;
                break;
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
            if (asft_chaSIV_encrypt(&cresp, &resp, resp_len, key_resp, resp_nonce_len)) {
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
    free(gw.password);

    gw.label = strdup(label);
    gw.password = strdup(password);

    if (!gw.label || !gw.password)
        goto error;

    return 0;

error:

    free(gw.label);
    free(gw.password);

    gw.label = NULL;
    gw.password = NULL;

    return -1;
}
