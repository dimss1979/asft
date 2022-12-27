#include <stdio.h>
#include <string.h>

#include "asft_proto.h"
#include "asft_crypto.h"
#include "asft_serial.h"

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
        unsigned char *buf;

        rv = asft_serial_receive((unsigned char**) &cpkt, &pkt_len);
        if (rv < 0) {
            fprintf(stderr, "Cannot receive from serial port\n");
            return 1;
        }

        if (rv && cpkt && pkt_len) {
            printf("Received encrypted packet:\n");
            buf = (unsigned char*) cpkt;
            for (int i = 0; i < pkt_len; i++)
                printf("%02X ", buf[i]);
            printf("\n");

            h = &cpkt->cmd.base;
            if (h->dst_addr != 1) {
                fprintf(stderr, "Wrong destination address %u\n", h->dst_addr);
                continue;
            }

            rv = asft_packet_decrypt(&pkt, cpkt, pkt_len, key);
            if (!rv && pkt) {
                printf("Received decrypted packet\n");
                buf = (unsigned char*) pkt;
                for (int i = 0; i < pkt_len; i++)
                    printf("%02X ", buf[i]);
                printf("\n");
            } else {
                fprintf(stderr, "Cannot decrypt packet\n");
            }
            printf("\n");
        }
    }

    return 0;
}
