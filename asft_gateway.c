#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <endian.h>
#include <sys/random.h>
#include <stdbool.h>

#include "asft_proto.h"
#include "asft_crypto.h"
#include "asft_serial.h"
#include "asft_misc.h"

#include "asft_gateway.h"

static unsigned char mkey[ASFT_KEY_LEN];
static unsigned char skey[ASFT_KEY_LEN];
static uint32_t packet_number = 0;
static struct asft_ecdh *ecdh = NULL;


static void process_resp_ecdh(struct asft_cmd_ecdh *resp, size_t resp_len)
{
    printf("Processing ECDH response\n");

    if (resp_len != sizeof(*resp))
        goto error;

    if (asft_ecdh_process(&ecdh, resp->public_key, skey))
        goto error;

    asft_dump(skey, sizeof(skey), "Session key");

    return;

error:

    fprintf(stderr, "Processing ECDH response failed\n");

    return;
}

int asft_gateway_loop()
{
    asft_packet *cpkt = NULL;

    memset(mkey, 0xaa, sizeof(mkey));
    getrandom(skey, sizeof(skey), 0);

    while(1)
    {
        int rv;
        struct asft_cmd_ecdh pkt;
        asft_packet *cresp = NULL;
        asft_packet *resp = NULL;
        size_t pkt_len = sizeof(pkt);
        uint64_t timeout;
        struct asft_base_hdr *h, *dh;
        bool got_response;
        uint32_t rx_packet_number;

        getrandom(&packet_number, sizeof(packet_number), 0);
        memset(&pkt, 0, pkt_len);
        pkt.base.dst_addr = 1;
        pkt.base.command = ASFT_REQ_ECDH_KEY;
        pkt.base.packet_number = htobe32(packet_number);
        memset(&pkt.base.tag, 0xaa, sizeof(pkt.base.tag));

        if (asft_ecdh_prepare(&ecdh, pkt.public_key)) {
            fprintf(stderr, "Cannot prepare ECDH\n");
            return 1;
        }

        asft_dump(&pkt, sizeof(pkt), "Prepared packet");

        rv = asft_packet_encrypt(&cpkt, &pkt, pkt_len, mkey);
        if (rv || !cpkt) {
            fprintf(stderr, "Cannot encrypt packet\n");
            return 1;
        }
        asft_dump(cpkt, pkt_len, "Encrypted packet");

        rv = asft_serial_send((unsigned char*) cpkt, pkt_len);
        if (rv < 0) {
            fprintf(stderr, "Cannot send packet\n");
            return 1;
        }

        got_response = false;
        timeout = asft_now() + 3000;
        while(timeout > asft_now() && !got_response) {
            rv = asft_serial_receive((unsigned char**) &cresp, &pkt_len);
            if (rv < 0) {
                fprintf(stderr, "Cannot receive response\n");
                return 1;
            }

            if (!cresp)
                continue;

            asft_dump(cresp, pkt_len, "Received response");

            h = &cresp->base;
            if (h->dst_addr != 0) {
                fprintf(stderr, "Wrong address %u\n", h->dst_addr);
                continue;
            }
            rx_packet_number = be32toh(h->packet_number);
            if (rx_packet_number != packet_number + 1) {
                fprintf(stderr, "Wrong packet number %u - expected %u\n", rx_packet_number, packet_number + 1);
                continue;
            }

            if (asft_packet_decrypt(&resp, cresp, pkt_len, mkey)) {
                fprintf(stderr, "Response decryption failed\n");
                continue;
            }

            asft_dump(resp, pkt_len, "Decrypted response");

            dh = &resp->base;
            switch (dh->command)
            {
                case ASFT_RSP_ECDH_KEY:
                    process_resp_ecdh(&resp->ecdh, pkt_len);
                    break;
                default:
                    fprintf(stderr, "Unknown command %x\n", dh->command);
            }
            got_response = true;
        };

        sleep(1);
    }

    return 0;
}
