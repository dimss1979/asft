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
    struct asft_key skey;
    struct asft_ecdh *ecdh;
} gw = { 0 };

static int gateway_init()
{
    if (!gw.label || !gw.password) {
        asft_error("Gateway not specified\n");
        goto error;
    }
    if(asft_kdf(&gw.ikey, gw.password)) {
        asft_error("Gateway '%s' initial key derivation failed\n", gw.label);
        goto error;
    };
    getrandom(&gw.skey, sizeof(gw.skey), 0);

    return 0;

error:

    return -1;
}

static void process_req_ecdh(struct asft_cmd_ecdh *req, size_t req_len)
{
    struct asft_cmd_ecdh resp = {0};
    asft_packet *cpkt = NULL;

    asft_debug("Processing ECDH request\n");

    if (req_len != sizeof(*req))
        goto error;

    if (asft_ecdh_prepare(&gw.ecdh, resp.public_key))
        goto error;

    if (asft_ecdh_process(&gw.ecdh, req->public_key, &gw.skey))
        goto error;

    asft_debug_dump(&gw.skey, sizeof(gw.skey), "Session key");

    resp.base.packet_number = htobe32(be32toh(req->base.packet_number) + 1);
    resp.base.command = ASFT_RSP_ECDH_KEY;

    asft_debug_dump(&resp, sizeof(resp), "Prepared ECDH response");

    if (asft_packet_encrypt(&cpkt, &resp, sizeof(resp), &gw.ikey))
        goto error;

    asft_debug_dump(cpkt, sizeof(resp), "Encrypted ECDH response");

    if (asft_serial_send((unsigned char*) cpkt, sizeof(resp)) < 0)
        goto error;

    return;

error:

    asft_error("Processing ECDH request failed\n");

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

        rv = asft_serial_receive((unsigned char**) &cpkt, &pkt_len);
        if (rv < 0) {
            asft_error("Cannot receive packet\n");
            return 1;
        }
        if (!rv || !cpkt || !pkt_len) {
            continue;
        }

        asft_debug_dump(cpkt, pkt_len, "Received packet");

        rv = asft_packet_decrypt(&pkt, cpkt, pkt_len, &gw.ikey);
        if (rv || !pkt) {
            asft_debug("Decryption failed\n");
            continue;
        }

        asft_debug_dump(pkt, pkt_len, "Decrypted packet");

        dh = &pkt->base;
        switch (dh->command)
        {
            case ASFT_REQ_ECDH_KEY:
                process_req_ecdh(&pkt->ecdh, pkt_len);
                break;
            default:
                asft_error("Unknown command %x\n", dh->command);
        }
    }

    return 0;
}
