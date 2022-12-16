// gcc -o asft -Wall -Werror *.c

#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "serial.h"

struct asft_config {
    bool is_master;
} config;

int main(int argc, char **argv)
{
    char *serial_port = NULL;
    char *baudrate = NULL;
    unsigned char tx_buf[400]; // TODO remove

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

    serial_port = argv[2];
    baudrate = argv[3];

    if (serial_open(serial_port, baudrate, sizeof(tx_buf))) {
        fprintf(stderr, "Cannot open serial port\n");
        return 1;
    }

    if (config.is_master) {
        memset(tx_buf, 'n', sizeof(tx_buf));
        tx_buf[0] = 'A';
        tx_buf[sizeof(tx_buf) - 1] = 'Z';
        while(1)
        {
            printf("Writing to serial\n");

            tx_buf[1] = '1';
            tx_buf[2] = 0xaa;
            tx_buf[3] = 0xaa;
            serial_write(tx_buf, 10);

            tx_buf[1] = '2';
            tx_buf[2] = 0x7e;
            tx_buf[3] = 0x7d;
            serial_write(tx_buf, 10);

            sleep(3);
        }
    }

    while (1) {
        int read_rv = 0;
        unsigned char *pkt = NULL;
        size_t pkt_len = 0;

        read_rv = serial_read(&pkt, &pkt_len);
        if (read_rv) {
            fprintf(stderr, "Serial port read error\n");
            return 1;
        }

        if (pkt && pkt_len) {
            printf("Received packet of %lu bytes\n", pkt_len);
        }
    }

    return 0;
}
