// gcc -o asft -Wall -Werror -std=gnu11 *.c -lcrypto
//
// or
//
// clang -o asft -Wall -Werror -std=gnu11 *.c -lcrypto

#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>

#include "asft_proto.h"
#include "asft_serial.h"
#include "asft_crypto.h"
#include "asft_node.h"
#include "asft_gateway.h"
#include "asft_misc.h"

typedef enum {
    OM_UNKNOWN,
    OM_GATEWAY,
    OM_NODE
} op_mode_t;

op_mode_t op_mode = OM_UNKNOWN;

static int read_config_file(char *filename)
{
    FILE *f = NULL;
    int rv = 1, line_number = 0;
    char buf[512];
    char *token;
    char delimiters[] = { ' ', '\t', '\n', '\r', 0 };

    f = fopen(filename, "r");
    if (!f) {
        asft_error("Cannot open file\n");
        goto error;
    }

    while (fgets(buf, sizeof(buf), f)) {
        line_number++;
        token = strtok(buf, delimiters);
        if (!token)
            continue;

        if (token[0] == '#') {
            continue;
        } else if (!strcmp(token, "debug")) {
            char *debug = strtok(NULL, delimiters);
            if (!debug) {
                asft_error("No debug level specified on line %i\n", line_number);
                goto error;
            }
            asft_set_debug(atoi(debug));
        } else if (!strcmp(token, "mode")) {
            char *mode = strtok(NULL, delimiters);
            if (!mode) {
                asft_error("No mode specified on line %i\n", line_number);
                goto error;
            }
            if (!strcmp(mode, "gateway")) {
                op_mode = OM_GATEWAY;
            } else if (!strcmp(mode, "node")) {
                op_mode = OM_NODE;
            } else {
                asft_error("Invalid mode on line %i: %s\n", line_number, mode);
                goto error;
            }
        } else if (!strcmp(token, "network")) {
            char *network_name = strtok(NULL, delimiters);
            if (!network_name) {
                asft_error("No network name specified on line %i\n", line_number);
                goto error;
            }
            if (asft_crypto_set_network_name(network_name)) {
                asft_error("Cannot set network name on line %i\n", line_number);
                goto error;
            }
        } else if (!strcmp(token, "port")) {
            char *device_name = strtok(NULL, delimiters);
            if (!device_name) {
                asft_error("No serial device name specified on line %i\n", line_number);
                goto error;
            }
            char *baudrate = strtok(NULL, delimiters);
            if (!baudrate) {
                asft_error("No baudrate specified on line %i\n", line_number);
                goto error;
            }
            if (asft_serial_init(device_name, baudrate, sizeof(asft_packet))) {
                asft_error("Cannot initialize serial port on line %i\n", line_number);
                goto error;
            }
        } else if (!strcmp(token, "retries")) {
            char *retries = strtok(NULL, delimiters);
            if (!retries) {
                asft_error("No retry count specified on line %i\n", line_number);
                goto error;
            }
            asft_gateway_set_retries(atoi(retries));
        } else if (!strcmp(token, "retry_timeout")) {
            char *retry_timeout = strtok(NULL, delimiters);
            if (!retry_timeout) {
                asft_error("No retry timeout specified on line %i\n", line_number);
                goto error;
            }
            asft_gateway_set_retry_timeout(atoi(retry_timeout));
        } else if (!strcmp(token, "pause_idle")) {
            char *pause_idle = strtok(NULL, delimiters);
            if (!pause_idle) {
                asft_error("No idle pause specified on line %i\n", line_number);
                goto error;
            }
            asft_gateway_set_pause_idle(atoi(pause_idle));
        } else if (!strcmp(token, "pause_error")) {
            char *pause_error = strtok(NULL, delimiters);
            if (!pause_error) {
                asft_error("No error pause specified on line %i\n", line_number);
                goto error;
            }
            asft_gateway_set_pause_error(atoi(pause_error));
        } else if (!strcmp(token, "node")) {
            char *label = strtok(NULL, delimiters);
            if (!label) {
                asft_error("Node label not specified on line %i\n", line_number);
                goto error;
            }
            char *password = strtok(NULL, delimiters);
            if (!password) {
                asft_error("Node password not specified on line %i\n", line_number);
                goto error;
            }
            if (asft_gateway_add_node(label, password)) {
                asft_error("Cannot add node on line %i\n", line_number);
                goto error;
            }
        } else if (!strcmp(token, "gateway")) {
            char *label = strtok(NULL, delimiters);
            if (!label) {
                asft_error("Gateway label not specified on line %i\n", line_number);
                goto error;
            }
            char *password = strtok(NULL, delimiters);
            if (!password) {
                asft_error("Gateway password not specified on line %i\n", line_number);
                goto error;
            }
            if (asft_node_set_gateway(label, password)) {
                asft_error("Cannot set gateway on line %i\n", line_number);
                goto error;
            }
        } else {
            asft_error("Unknown option on line %i: %s\n", line_number, token);
            goto error;
        }
    }

    rv = 0;

error:

    if (f)
        fclose(f);

    return rv;
}

int main(int argc, char **argv)
{
    int rv = 0;

    if (argc < 2) {
        asft_error("Usage: asft <config_file>\n");
        return 1;
    }

    if (read_config_file(argv[1])) {
        asft_error("Error while reading configuration file\n");
        return 1;
    }

    if (asft_crypto_init()) {
        asft_error("Cannot initialize crypto\n");
        return 1;
    }

    switch (op_mode) {
        case OM_GATEWAY:
            rv = asft_gateway_loop();
            break;
        case OM_NODE:
            rv = asft_node_loop();
            break;
        default:
            asft_error("Operation mode not specified\n");
            return 1;
    };

    return !!rv;
}
