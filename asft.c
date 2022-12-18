// gcc -o asft -Wall -Werror *.c

#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "asft_serial.h"

struct asft_config {
    bool is_master;
} config;

int main(int argc, char **argv)
{
    char *serial_port_name;
    char *baudrate;
    asft_serial serial_port;
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

    serial_port_name = argv[2];
    baudrate = argv[3];

    serial_port = asft_serial_open(serial_port_name, baudrate, sizeof(tx_buf));
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
            printf("Sending packets\n");

            tx_buf[1] = '1';
            tx_buf[2] = 0xaa;
            tx_buf[3] = 0xaa;
            rv = asft_serial_send(serial_port, tx_buf, 10);
            if (rv) {
                fprintf(stderr, "Cannot send to serial port\n");
                return 1;
            }

            tx_buf[1] = '2';
            tx_buf[2] = 0x7e;
            tx_buf[3] = 0x7d;
            rv = asft_serial_send(serial_port, tx_buf, 10);
            if (rv) {
                fprintf(stderr, "Cannot send to serial port\n");
                return 1;
            }

            sleep(3);
        }
    }

    while (1) {
        int rv = 0;
        unsigned char *pkt = NULL;
        size_t pkt_len = 0;

        rv = asft_serial_receive(serial_port, &pkt, &pkt_len);
        if (rv) {
            fprintf(stderr, "Serial port reception error\n");
            return 1;
        }

        if (pkt && pkt_len) {
            printf("Received packet of %lu bytes\n", pkt_len);
        }
    }

    return 0;
}
