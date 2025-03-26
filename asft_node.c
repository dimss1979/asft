#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif /*_GNU_SOURCE*/

#include <stdio.h>
#include <string.h>
#include <sys/random.h>
#include <endian.h>
#include <stdlib.h>
#include <stdbool.h>

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

    struct asft_key ikey;
    struct asft_key skey;
    struct asft_ecdh *ecdh;
    bool have_skey;

    uint32_t last_packet_number;

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
    if(asft_kdf(&gw.ikey, gw.password, strlen(gw.password))) {
        asft_error("Gateway initial key derivation failed\n");
        goto error;
    }
    gw.blob_tx.auth_key = gw.ikey.auth_blob;
    gw.blob_rx.auth_key = gw.ikey.auth_blob;
    if (asprintf(&gw.upload_dir, "to_%s", gw.label) < 0)
        goto error;
    if (asprintf(&gw.download_dir, "from_%s", gw.label) < 0)
        goto error;

    return 0;

error:

    return -1;
}

static void process_req_ecdh(asft_packet *req, size_t req_len, asft_packet *resp, size_t *resp_len)
{
    if (req_len != sizeof(req->ecdh))
        goto error;

    if (asft_ecdh_prepare(&gw.ecdh, resp->ecdh.public_key))
        goto error;

    if (asft_ecdh_process(&gw.ecdh, req->ecdh.public_key, &gw.skey))
        goto error;

    resp->base.command = ASFT_RSP_ECDH_KEY;
    *resp_len = sizeof(resp->ecdh);
    gw.have_skey = true;
    gw.last_packet_number = 0;

    asft_info("Session key exchange complete\n");

    return;

error:

    asft_error("Session key exchange failed\n");

    return;
}

static void process_req_data(asft_packet *req, size_t req_len, asft_packet *resp, size_t *resp_len, bool have_data)
{
    uint8_t ack;
    if (have_data) {
        asft_blob_rx_receive(&gw.blob_rx, be16toh(req->data.block_idx), req->data.data, gw.download_dir);
        ack = req->data.ack;
    } else {
        ack = req->nodata.ack;
    }
    asft_blob_tx_ack(&gw.blob_tx, ack);
    asft_blob_tx_init(&gw.blob_tx, gw.upload_dir);

    if (gw.blob_tx.blob) {
        resp->base.command = ASFT_RSP_DATA;
        *resp_len = sizeof(resp->data);

        uint16_t block_idx = 0;
        asft_blob_tx_send(&gw.blob_tx, &block_idx, resp->data.data);
        resp->data.block_idx = htobe16(block_idx);
        asft_blob_rx_get_ack(&gw.blob_rx, &resp->data.ack);
    } else {
        resp->base.command = ASFT_RSP_NODATA;
        *resp_len = sizeof(resp->nodata);
        asft_blob_rx_get_ack(&gw.blob_rx, &resp->nodata.ack);
    }
}

int asft_node_loop()
{
    if (gateway_init()) {
        asft_error("Gateway initialization failed\n");
        return 1;
    }
    asft_debug("Gateway initialized\n");

    while (1) {
        int rv = 0;
        asft_packet *pkt = NULL;
        asft_packet *cpkt = NULL;
        size_t pkt_len = 0;
        struct asft_base_hdr *dh;
        asft_packet resp, *cresp = NULL;
        size_t resp_len = 0;
        enum {D_NKEY, D_IKEY, D_SKEY} decryption_key = D_NKEY;
        uint32_t rx_packet_number;

        rv = asft_serial_receive((unsigned char**) &cpkt, &pkt_len);
        if (rv < 0) {
            asft_error("Cannot receive packet\n");
            return 1;
        }
        if (!rv || !cpkt || !pkt_len) {
            continue;
        }

        asft_debug("Received %u bytes\n", pkt_len);

        if (gw.have_skey) {
            rv = asft_packet_decrypt(&pkt, cpkt, pkt_len, &gw.skey);
            if (!rv && pkt) {
                decryption_key = D_SKEY;
                goto decrypted;
            }
        }
        rv = asft_packet_decrypt(&pkt, cpkt, pkt_len, &gw.ikey);
        if (!rv && pkt) {
            decryption_key = D_IKEY;
            goto decrypted;
        }

        asft_debug("Decryption failed\n");
        continue;

decrypted:

        dh = &pkt->base;

        if (dh->command == ASFT_REQ_ECDH_KEY && decryption_key != D_IKEY) {
            asft_error("Key exchange must be encrypted with initial key\n");
            continue;
        } else if (dh->command != ASFT_REQ_ECDH_KEY && decryption_key != D_SKEY) {
            asft_error("Command %u is not encrypted with session key\n", dh->command);
            continue;
        }

        rx_packet_number = be32toh(pkt->base.packet_number);
        if (decryption_key == D_SKEY && rx_packet_number <= gw.last_packet_number) {
            asft_error("Packet number %u, last was %u\n", rx_packet_number, gw.last_packet_number);
            continue;
        }
        if (decryption_key != D_IKEY) {
            gw.last_packet_number = rx_packet_number;
        }

        struct asft_key *ckey = &gw.skey;
        switch (dh->command)
        {
            case ASFT_REQ_ECDH_KEY:
                process_req_ecdh(pkt, pkt_len, &resp, &resp_len);
                ckey = &gw.ikey;
                break;
            case ASFT_REQ_NODATA:
                process_req_data(pkt, pkt_len, &resp, &resp_len, false);
                break;
            case ASFT_REQ_DATA:
                process_req_data(pkt, pkt_len, &resp, &resp_len, true);
                break;
            default:
                asft_error("Unknown command %u\n", dh->command);
        }

        if (resp_len) {
            resp.base.packet_number = htobe32(rx_packet_number);

            if (asft_packet_encrypt(&cresp, &resp, resp_len, ckey)) {
                asft_error("Response encryption failed\n");
                return 1;
            }

            asft_debug("Sending response %u bytes\n", resp_len);

            if (asft_serial_send((unsigned char*) cresp, resp_len) < 0) {
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
