#include <stdio.h>
#include <string.h>

#include "asft_crypto.h"
#include "asft_serial.h"

#include "asft_node.h"

static unsigned char key[ASFT_CRYPTO_KEY_SIZE];

int asft_node_loop()
{
    memset(key, 0xaa, sizeof(key));

    while (1) {
        int rv = 0;
        unsigned char *cpkt = NULL;
        size_t cpkt_len = 0;
        unsigned char *pkt = NULL;
        size_t pkt_len = 0;

        rv = asft_serial_receive(&cpkt, &cpkt_len);
        if (rv < 0) {
            fprintf(stderr, "Cannot receive from serial port\n");
            return 1;
        }

        if (rv && cpkt && cpkt_len) {
            printf("Received encrypted packet:\n");
            for (int i = 0; i < cpkt_len; i++)
                printf("%02X ", cpkt[i]);
            printf("\n");

            rv = asft_packet_decrypt(&pkt, &pkt_len, cpkt, cpkt_len, key, 123);
            if (!rv && pkt && pkt_len) {
                printf("Received decrypted packet\n");
                for (int i = 0; i < pkt_len; i++)
                    printf("%02X ", pkt[i]);
                printf("\n");
            } else {
                fprintf(stderr, "Cannot decrypt packet\n");
            }
            printf("\n");
        }
    }

    return 0;
}
