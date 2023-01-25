#include <stdio.h>
#include <string.h>
#include <sys/random.h>
#include <endian.h>

#include "asft_proto.h"
#include "asft_crypto.h"
#include "asft_serial.h"
#include "asft_misc.h"

#include "asft_node.h"

static struct asft_ecdh *ecdh = NULL;
static unsigned char mkey[ASFT_KEY_LEN];
static unsigned char skey[ASFT_KEY_LEN];

static void process_req_ecdh(struct asft_cmd_ecdh *req, size_t req_len)
{
    struct asft_cmd_ecdh resp = {0};
    asft_packet *cpkt = NULL;

    printf("Processing ECDH request\n");

    if (req_len != sizeof(*req))
        goto error;

    if (asft_ecdh_prepare(&ecdh, resp.public_key))
        goto error;

    if (asft_ecdh_process(&ecdh, req->public_key, skey))
        goto error;

    asft_dump(skey, sizeof(skey), "Session key");

    resp.base.dst_addr = 0;
    resp.base.packet_number = htobe32(be32toh(req->base.packet_number) + 1);
    resp.base.command = ASFT_RSP_ECDH_KEY;

    asft_dump(&resp, sizeof(resp), "Prepared ECDH response");

    if (asft_packet_encrypt(&cpkt, &resp, sizeof(resp), mkey))
        goto error;

    asft_dump(cpkt, sizeof(resp), "Encrypted ECDH response");

    if (asft_serial_send((unsigned char*) cpkt, sizeof(resp)) < 0)
        goto error;

    return;

error:

    fprintf(stderr, "Processing ECDH request failed\n");

    return;
}

int asft_node_loop()
{
    memset(mkey, 0xaa, sizeof(mkey));
    getrandom(skey, sizeof(skey), 0);

    while (1) {
        int rv = 0;
        asft_packet *pkt = NULL;
        asft_packet *cpkt = NULL;
        size_t pkt_len = 0;
        struct asft_base_hdr *h, *dh;

        rv = asft_serial_receive((unsigned char**) &cpkt, &pkt_len);
        if (rv < 0) {
            fprintf(stderr, "Cannot receive packet\n");
            return 1;
        }
        if (!rv || !cpkt || !pkt_len) {
            continue;
        }

        asft_dump(cpkt, pkt_len, "Received packet");

        h = &cpkt->base;
        if (h->dst_addr != 1) {
            fprintf(stderr, "Wrong address %u\n", h->dst_addr);
            continue;
        }

        rv = asft_packet_decrypt(&pkt, cpkt, pkt_len, mkey);
        if (rv || !pkt) {
            fprintf(stderr, "Decryption failed\n");
            continue;
        }

        asft_dump(pkt, pkt_len, "Decrypted packet");

        dh = &pkt->base;
        switch (dh->command)
        {
            case ASFT_REQ_ECDH_KEY:
                process_req_ecdh(&pkt->ecdh, pkt_len);
                break;
            default:
                fprintf(stderr, "Unknown command %x\n", dh->command);
        }
    }

    return 0;
}
