// gcc -o asft -Wall -Werror *.c -lcrypto

#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#include "asft_proto.h"
#include "asft_serial.h"
#include "asft_crypto.h"
#include "asft_node.h"
#include "asft_gateway.h"

int main(int argc, char **argv)
{
    char *serial_port_name;
    char *baudrate;
    bool is_gateway = false;
    int rv = 0;

    if (argc < 4) {
        fprintf(stderr, "Usage: asft <mode> <serial_port> <baudrate>\n");
        return 1;
    }

    if (!strcmp(argv[1], "gateway")) {
        printf("Gateway mode\n");
        is_gateway = true;
    } else if (!strcmp(argv[1], "node")) {
        printf("Node mode\n");
    } else {
        fprintf(stderr, "Wrong operation mode: %s\n", argv[1]);
        return 1;
    }

    serial_port_name = argv[2];
    baudrate = argv[3];

    if (asft_crypto_init()) {
        fprintf(stderr, "Cannot initialize crypto\n");
        return 1;
    }

    if (asft_serial_init(serial_port_name, baudrate, sizeof(asft_packet))) {
        fprintf(stderr, "Cannot initialize serial port\n");
        return 1;
    }

    if (is_gateway) {
        rv = asft_gateway_loop();
    } else {
        rv = asft_node_loop();
    }

    return !!rv;
}
