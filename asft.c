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

    if (serial_open(serial_port, baudrate)) {
        fprintf(stderr, "Cannot open serial port\n");
        return 1;
    }

    printf("Writing to serial\n");
    {
        // TODO remove
        unsigned char buf[400];
        memset(buf, 'n', sizeof(buf));
        buf[0] = 'A';
        buf[1] = '1';
        buf[sizeof(buf) - 1] = 'Z';
        serial_write(buf, sizeof(buf));

        sleep(1);

        buf[1] = '2';
        serial_write(buf, sizeof(buf));
    }

    while (1) {
        int read_rv = 0;
        unsigned char *read_buf = NULL;
        size_t read_buf_len = 0;

        read_rv = serial_read(&read_buf, &read_buf_len);
        if (read_rv < 0) {
            fprintf(stderr, "Serial port read error\n");
            return 1;
        }

        if (read_buf && read_buf_len) {
            // TODO process received frame
        }

        // TODO process timeouts
    }

    return 0;
}
