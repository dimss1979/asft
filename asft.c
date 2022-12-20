// gcc -o asft -Wall -Werror *.c -lcrypto

#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "asft_serial.h"
#include "asft_crypto.h"

struct asft_config {
    bool is_master;
} config;

int main(int argc, char **argv)
{
    char *serial_port_name;
    char *baudrate;
    asft_serial serial_port;
    unsigned char tx_buf[30];
    unsigned char key[ASFT_CRYPTO_KEY_SIZE];
    size_t cpkt_len_max;

    if (argc < 4) {
        fprintf(stderr, "Usage: asft <mode> <serial_port> <baudrate>\n");
        return 1;
    }

    if (!strcmp(argv[1], "master")) {
        printf("Master mode\n");
        config.is_master = true;
    } else if (!strcmp(argv[1], "slave")) {
        printf("Slave mode\n");
        config.is_master = false;
    } else {
        fprintf(stderr, "Wrong operation mode: %s\n", argv[1]);
        return 1;
    }

    serial_port_name = argv[2];
    baudrate = argv[3];

    memset(key, 0xaa, sizeof(key));
    cpkt_len_max = asft_crypto_init(sizeof(tx_buf));
    if (!cpkt_len_max) {
        fprintf(stderr, "Cannot initialize crypto\n");
        return 1;
    }

    serial_port = asft_serial_open(serial_port_name, baudrate, cpkt_len_max);
    if (!serial_port) {
        fprintf(stderr, "Cannot open serial port\n");
        return 1;
    }

    if (config.is_master) {
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

            rv = asft_packet_encrypt(&cpkt, &cpkt_len, tx_buf, sizeof(tx_buf), key);
            if (rv || !cpkt || !cpkt_len) {
                fprintf(stderr, "Cannot encrypt packet\n");
                return 1;
            }
            printf("Sending encrypted packet:\n");
            for (int i = 0; i < cpkt_len; i++)
                printf("%02X ", cpkt[i]);
            printf("\n\n");

            rv = asft_serial_send(serial_port, (unsigned char*) cpkt, cpkt_len);
            if (rv) {
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

            rv = asft_packet_encrypt(&cpkt, &cpkt_len, tx_buf, sizeof(tx_buf), key);
            if (rv || !cpkt || !cpkt_len) {
                fprintf(stderr, "Cannot encrypt packet\n");
                return 1;
            }
            printf("Sending encrypted packet:\n");
            for (int i = 0; i < cpkt_len; i++)
                printf("%02X ", cpkt[i]);
            printf("\n\n");

            rv = asft_serial_send(serial_port, (unsigned char*) cpkt, cpkt_len);
            if (rv) {
                fprintf(stderr, "Cannot send to serial port\n");
                return 1;
            }

            sleep(3);
        }
    }

    while (1) {
        int rv = 0;
        unsigned char *cpkt = NULL;
        size_t cpkt_len = 0;
        unsigned char *pkt = NULL;
        size_t pkt_len = 0;

        rv = asft_serial_receive(serial_port, &cpkt, &cpkt_len);
        if (rv) {
            fprintf(stderr, "Serial port reception error\n");
            return 1;
        }

        if (cpkt && cpkt_len) {
            printf("Received encrypted packet:\n");
            for (int i = 0; i < cpkt_len; i++)
                printf("%02X ", cpkt[i]);
            printf("\n");

            rv = asft_packet_decrypt(&pkt, &pkt_len, cpkt, cpkt_len, key);
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
