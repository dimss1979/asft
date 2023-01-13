#include <stdio.h>
#include <string.h>

#include "asft_proto.h"
#include "asft_crypto.h"
#include "asft_serial.h"
#include "asft_misc.h"

#include "asft_node.h"

int asft_node_loop()
{
    static unsigned char key[ASFT_KEY_LEN];

    memset(key, 0xaa, sizeof(key));

    while (1) {
        int rv = 0;
        asft_packet *pkt = NULL;
        asft_packet *cpkt = NULL;
        size_t pkt_len = 0;
        struct asft_base_hdr *h;
        struct asft_cmd_hdr *ch;

        rv = asft_serial_receive((unsigned char**) &cpkt, &pkt_len);
        if (rv < 0) {
            fprintf(stderr, "Cannot receive packet\n");
            return 1;
        }
        if (!rv || !cpkt || !pkt_len) {
            continue;
        }

        asft_dump(cpkt, pkt_len, "Received packet");

        h = &cpkt->cmd.base;
        if (h->dst_addr != 1) {
            fprintf(stderr, "Wrong address %u\n", h->dst_addr);
            continue;
        }

        rv = asft_packet_decrypt(&pkt, cpkt, pkt_len, key);
        if (rv || !pkt) {
            fprintf(stderr, "Decryption failed\n");
            continue;
        }

        asft_dump(pkt, pkt_len, "Decrypted packet");

        ch = &pkt->cmd.cmd;
        switch (ch->command)
        {
            case ASFT_REQ_ECDH_KEY:
                printf("ECDH command\n");
                break;
            default:
                fprintf(stderr, "Unknown command %x\n", ch->command);
        }
    }

    return 0;
}
