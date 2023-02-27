#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <endian.h>
#include <sys/random.h>
#include <stdbool.h>
#include <stdlib.h>

#include "asft_proto.h"
#include "asft_crypto.h"
#include "asft_serial.h"
#include "asft_misc.h"

#include "asft_gateway.h"

struct node
{
    struct node *next;
    char *label;
    char *password;

    struct asft_key ikey;
    struct asft_key skey;
    struct asft_ecdh *ecdh;
    uint32_t packet_number;
};

static struct node *node_first = NULL;
static unsigned int node_cnt = 0;

static int retries = 5;
static int retry_timeout = 5;
static int pause_idle = 10;
static int pause_error = 10;

static int nodes_init()
{
    struct node *n;

    if (!node_cnt) {
        asft_error("No nodes configured\n");
        goto error;
    }

    n = node_first;
    while (n) {
        if (asft_kdf(&n->ikey, n->password)) {
            asft_error("Node '%s' initial key derivation failed\n", n->label);
            goto error;
        }
        getrandom(&n->skey, sizeof(n->skey), 0);

        n = n->next;
    }

    return 0;

error:

    return -1;
}

static void process_resp_ecdh(struct node *n, struct asft_cmd_ecdh *resp, size_t resp_len)
{
    asft_debug("Processing ECDH response\n");

    if (resp_len != sizeof(*resp))
        goto error;

    if (asft_ecdh_process(&n->ecdh, resp->public_key, &n->skey))
        goto error;

    asft_debug_dump(&n->skey, sizeof(n->skey), "Session key");

    return;

error:

    asft_error("Processing ECDH response failed\n");

    return;
}

void asft_gateway_set_retries(int new_retries)
{
    retries = new_retries;
}

void asft_gateway_set_retry_timeout(int new_timeout)
{
    retry_timeout = new_timeout;
}

void asft_gateway_set_pause_idle(int new_pause_idle)
{
    pause_idle = new_pause_idle;
}

void asft_gateway_set_pause_error(int new_pause_error)
{
    pause_error = new_pause_error;
}

int asft_gateway_add_node(char *label, char *password)
{
    struct node *new;

    new = malloc(sizeof(*new));
    if (!new)
        goto error;
    memset(new, 0, sizeof(*new));

    new->label = strdup(label);
    if (!new->label)
        goto error;

    new->password = strdup(password);
    if (!new->password)
        goto error;

    new->next = node_first;
    node_first = new;
    node_cnt++;

    return 0;

error:

    if (new) {
        if (new->label)
            free(new->label);
        if (new->password)
            free(new->password);
        free(new);
    }

    return -1;
}

int asft_gateway_loop()
{
    asft_packet *cpkt = NULL;
    struct node *n;

    if (nodes_init()) {
        asft_error("Node initialization failed\n");
        return 1;
    }

    n = node_first;

    while(1)
    {
        int rv;
        struct asft_cmd_ecdh pkt;
        asft_packet *cresp = NULL;
        asft_packet *resp = NULL;
        size_t pkt_len = sizeof(pkt);
        uint64_t timeout;
        struct asft_base_hdr *dh;
        bool got_response;
        uint32_t rx_packet_number;

        getrandom(&n->packet_number, sizeof(n->packet_number), 0);
        memset(&pkt, 0, pkt_len);
        pkt.base.command = ASFT_REQ_ECDH_KEY;
        pkt.base.packet_number = htobe32(n->packet_number);
        memset(&pkt.base.tag, 0xaa, sizeof(pkt.base.tag));

        if (asft_ecdh_prepare(&n->ecdh, pkt.public_key)) {
            asft_error("Cannot prepare ECDH\n");
            return 1;
        }

        asft_debug_dump(&pkt, sizeof(pkt), "Prepared packet");

        rv = asft_packet_encrypt(&cpkt, &pkt, pkt_len, &n->ikey);
        if (rv || !cpkt) {
            asft_error("Cannot encrypt packet\n");
            return 1;
        }
        asft_debug_dump(cpkt, pkt_len, "Encrypted packet");

        rv = asft_serial_send((unsigned char*) cpkt, pkt_len);
        if (rv < 0) {
            asft_error("Cannot send packet\n");
            return 1;
        }

        got_response = false;
        timeout = asft_now() + retry_timeout * 1000;
        while(timeout > asft_now() && !got_response) {
            rv = asft_serial_receive((unsigned char**) &cresp, &pkt_len);
            if (rv < 0) {
                asft_error("Cannot receive response\n");
                return 1;
            }

            if (!cresp)
                continue;

            asft_debug_dump(cresp, pkt_len, "Received response");

            if (asft_packet_decrypt(&resp, cresp, pkt_len, &n->ikey)) {
                asft_debug("Response decryption failed\n");
                continue;
            }

            asft_debug_dump(resp, pkt_len, "Decrypted response");

            dh = &resp->base;
            rx_packet_number = be32toh(dh->packet_number);
            if (rx_packet_number != n->packet_number + 1) {
                asft_error("Wrong packet number %u - expected %u\n", rx_packet_number, n->packet_number + 1);
                continue;
            }

            switch (dh->command)
            {
                case ASFT_RSP_ECDH_KEY:
                    process_resp_ecdh(n, &resp->ecdh, pkt_len);
                    break;
                default:
                    asft_error("Unknown command %x\n", dh->command);
            }
            got_response = true;
        };

        sleep(pause_idle);
    }

    return 0;
}
