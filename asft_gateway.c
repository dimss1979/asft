#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include "asft_crypto.h"
#include "asft_serial.h"

#include "asft_gateway.h"

static unsigned char tx_buf[30];
static unsigned char key[ASFT_CRYPTO_KEY_SIZE];

int asft_gateway_loop()
{
    memset(key, 0xaa, sizeof(key));

    memset(tx_buf, 'n', sizeof(tx_buf));
    tx_buf[0] = 'A';
    tx_buf[sizeof(tx_buf) - 1] = 'Z';

    while(1)
    {
        int rv;
        unsigned char *cpkt = NULL;
        size_t cpkt_len = 0;

        tx_buf[1] = '1';
        tx_buf[2] = 0xaa;
        tx_buf[3] = 0xaa;
        printf("Sending packet:\n");
        for (int i = 0; i < sizeof(tx_buf); i++)
            printf("%02X ", tx_buf[i]);
        printf("\n");

        rv = asft_packet_encrypt(&cpkt, &cpkt_len, tx_buf, sizeof(tx_buf), key, 123);
        if (rv || !cpkt || !cpkt_len) {
            fprintf(stderr, "Cannot encrypt packet\n");
            return 1;
        }
        printf("Sending encrypted packet:\n");
        for (int i = 0; i < cpkt_len; i++)
            printf("%02X ", cpkt[i]);
        printf("\n\n");

        rv = asft_serial_send((unsigned char*) cpkt, cpkt_len);
        if (rv < 0) {
            fprintf(stderr, "Cannot send to serial port\n");
            return 1;
        }

        tx_buf[1] = '2';
        tx_buf[2] = 0x7e;
        tx_buf[3] = 0x7d;
        printf("Sending packet:\n");
        for (int i = 0; i < sizeof(tx_buf); i++)
            printf("%02X ", tx_buf[i]);
        printf("\n");

        rv = asft_packet_encrypt(&cpkt, &cpkt_len, tx_buf, sizeof(tx_buf), key, 123);
        if (rv || !cpkt || !cpkt_len) {
            fprintf(stderr, "Cannot encrypt packet\n");
            return 1;
        }
        printf("Sending encrypted packet:\n");
        for (int i = 0; i < cpkt_len; i++)
            printf("%02X ", cpkt[i]);
        printf("\n\n");

        rv = asft_serial_send((unsigned char*) cpkt, cpkt_len);
        if (rv < 0) {
            fprintf(stderr, "Cannot send to serial port\n");
            return 1;
        }

        sleep(3);
    }

    return 0;
}
