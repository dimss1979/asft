#include <stdio.h>
#include <string.h>
#include <sys/random.h>
#include <endian.h>
#include <stdlib.h>

#include "asft_proto.h"
#include "asft_crypto.h"
#include "asft_serial.h"
#include "asft_misc.h"

#include "asft_node.h"

static struct gateway
{
    char *label;
    char *password;

    struct asft_key ikey;
    struct asft_key tkey;
    struct asft_key skey;
    struct asft_ecdh *ecdh;

    uint32_t last_packet_number;
} gw = { 0 };

static int gateway_init()
{
    if (!gw.label || !gw.password) {
        asft_error("Gateway not specified\n");
        goto error;
    }
    if(asft_kdf(&gw.ikey, gw.password)) {
        asft_error("Gateway initial key derivation failed\n");
        goto error;
    };
    getrandom(&gw.skey, sizeof(gw.skey), 0);

    return 0;

error:

    return -1;
}

static void process_error(asft_packet *resp, size_t *resp_len)
{
    asft_error("Indicate error to gateway\n");

    resp->base.command = ASFT_RSP_ERROR;
    *resp_len = sizeof(resp->base);

    return;
}

static void process_req_ecdh(asft_packet *req, size_t req_len, asft_packet *resp, size_t *resp_len)
{
    if (req_len != sizeof(req->ecdh))
        goto error;

    if (asft_ecdh_prepare(&gw.ecdh, resp->ecdh.public_key))
        goto error;

    if (asft_ecdh_process(&gw.ecdh, req->ecdh.public_key, &gw.tkey))
        goto error;

    resp->base.command = ASFT_RSP_ECDH_KEY;
    *resp_len = sizeof(resp->ecdh);

    asft_info("Session key exchange complete\n");

    return;

error:

    asft_error("Session key exchange failed\n");
    process_error(resp, resp_len);

    return;
}

static void process_req_get_file(asft_packet *req, size_t req_len, asft_packet *resp, size_t *resp_len)
{
    if (req_len != sizeof(req->base))
        goto error;

    resp->base.command = ASFT_RSP_GET_FILE_NAK;
    *resp_len = sizeof(resp->base);

    asft_debug("Upload request complete\n");

    return;

error:

    asft_error("Upload request failed\n");
    process_error(resp, resp_len);

    return;
}


int asft_node_set_gateway(char *label, char *password)
{
    gw.label = strdup(label);
    if (!gw.label)
        goto error;

    gw.password = strdup(password);
    if (!gw.password)
        goto error;

    return 0;

error:

    if (gw.label)
        free(gw.label);
    if (gw.password)
        free(gw.password);

    return -1;
}

int asft_node_loop()
{
    if (gateway_init()) {
        asft_error("Gateway initialization failed\n");
        return 1;
    }

    while (1) {
        int rv = 0;
        asft_packet *pkt = NULL;
        asft_packet *cpkt = NULL;
        size_t pkt_len = 0;
        struct asft_base_hdr *dh;
        asft_packet resp, *cresp = NULL;
        size_t resp_len = 0;
        enum {D_NKEY, D_IKEY, D_TKEY, D_SKEY} decryption_key = D_NKEY;
        uint32_t rx_packet_number;
        struct asft_key *ckey = &gw.skey;

        rv = asft_serial_receive((unsigned char**) &cpkt, &pkt_len);
        if (rv < 0) {
            asft_error("Cannot receive packet\n");
            return 1;
        }
        if (!rv || !cpkt || !pkt_len) {
            continue;
        }

        asft_debug("Received %u bytes\n", pkt_len);

        rv = asft_packet_decrypt(&pkt, cpkt, pkt_len, &gw.skey);
        if (!rv && pkt) {
            decryption_key = D_SKEY;
            goto decrypted;
        }
        rv = asft_packet_decrypt(&pkt, cpkt, pkt_len, &gw.ikey);
        if (!rv && pkt) {
            decryption_key = D_IKEY;
            goto decrypted;
        }
        rv = asft_packet_decrypt(&pkt, cpkt, pkt_len, &gw.tkey);
        if (!rv && pkt) {
            decryption_key = D_TKEY;
            goto decrypted;
        }

        asft_debug("Decryption failed\n");
        continue;

decrypted:

        asft_debug("Decrypted using key %u\n", decryption_key);

        dh = &pkt->base;

        if (dh->command == ASFT_REQ_ECDH_KEY && decryption_key != D_IKEY) {
            asft_error("Key exchange must be encrypted with initial key\n");
            continue;
        } else if (dh->command != ASFT_REQ_GET_FILE && decryption_key == D_TKEY) {
            asft_error("Command %u is encrypted with temporary key\n", dh->command);
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

        if (decryption_key == D_TKEY)
            memcpy(&gw.skey, &gw.tkey, sizeof(gw.skey));

        switch (dh->command)
        {
            case ASFT_REQ_ECDH_KEY:
                process_req_ecdh(pkt, pkt_len, &resp, &resp_len);
                ckey = &gw.ikey;
                break;
            case ASFT_REQ_GET_FILE:
                process_req_get_file(pkt, pkt_len, &resp, &resp_len);
                break;
            default:
                asft_error("Unknown command %u\n", dh->command);
                process_error(&resp, &resp_len);
        }

        resp.base.packet_number = htobe32(rx_packet_number + 1);

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

    return 0;
}
