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
    enum asft_command cmd;
    unsigned int retry;
    uint64_t pause_until;

    asft_packet pkt;
    unsigned int pkt_len;
};

static struct node *node_first = NULL;
static unsigned int node_cnt = 0;

static int retries = 5;
static int retry_timeout = 5;
static int pause_idle = 10;
static int pause_error = 10;

static void node_set_idle(struct node *n)
{
    n->cmd = ASFT_REQ_ECDH_KEY;
    getrandom(&n->packet_number, sizeof(n->packet_number), 0);
    n->pause_until = 1000 * pause_idle + asft_now();
    n->retry = 0;
}

static void node_set_error(struct node *n)
{
    n->cmd = ASFT_REQ_ECDH_KEY;
    getrandom(&n->packet_number, sizeof(n->packet_number), 0);
    n->pause_until = 1000 * pause_error + asft_now();
    n->retry = 0;
}

static struct node *node_pick_next(struct node *cur)
{
    struct node *n = NULL;
    uint64_t now = asft_now();

    if (cur)
        n = cur->next;

    for (unsigned int i = 0; i < node_cnt; i++) {
        if (!n)
            n = node_first;

        if (n->pause_until <= now)
            return n;

        n = n->next;
    }

    return NULL;
}

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

        n->cmd = ASFT_REQ_ECDH_KEY;
        getrandom(&n->packet_number, sizeof(n->packet_number), 0);
        n->pause_until = 0;
        n->retry = 0;

        n = n->next;
    }

    return 0;

error:

    return -1;
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

static void process_resp_ecdh(struct node *n, struct asft_cmd_ecdh *resp, size_t resp_len)
{
    asft_debug("Processing ECDH response\n");

    if (resp_len != sizeof(*resp))
        goto error;

    if (asft_ecdh_process(&n->ecdh, resp->public_key, &n->skey))
        goto error;

    asft_debug_dump(&n->skey, sizeof(n->skey), "Session key");
    node_set_idle(n);

    return;

error:

    asft_error("Processing ECDH response failed\n");

    return;
}

int asft_gateway_loop()
{
    int rv;
    struct node *n = NULL;
    asft_packet *cpkt = NULL;
    uint64_t timeout;
    asft_packet *cresp = NULL;
    asft_packet *resp = NULL;
    struct asft_base_hdr *dh;
    bool got_response;
    uint32_t rx_packet_number;
    size_t rx_packet_len;

    if (nodes_init()) {
        asft_error("Node initialization failed\n");
        return 1;
    }

    while(1)
    {
        n = node_pick_next(n);

        if (n) {
            n->pkt.base.packet_number = htobe32(n->packet_number);
            n->packet_number += 2;

            if (n->retry) {
                asft_debug("Node '%s' retry %u\n", n->label, n->retry);
            } else {
                n->pkt.base.command = n->cmd;

                switch(n->cmd)
                {
                    case ASFT_REQ_ECDH_KEY:
                        asft_info("Node '%s' key exchange\n", n->label);
                        if (asft_ecdh_prepare(&n->ecdh, n->pkt.ecdh.public_key)) {
                            asft_error("Cannot prepare ECDH\n");
                            return 1;
                        }
                        n->pkt_len = sizeof(n->pkt.ecdh);
                        break;
                    default:
                        asft_error("Node '%s' unknown next command %i\n", n->label, n->cmd);
                        return 1;
                }
            }

            asft_debug_dump(&n->pkt, n->pkt_len, "Prepared packet");

            rv = asft_packet_encrypt(&cpkt, &n->pkt, n->pkt_len, &n->ikey);
            if (rv || !cpkt) {
                asft_error("Cannot encrypt packet\n");
                return 1;
            }

            asft_debug_dump(cpkt, n->pkt_len, "Encrypted packet");

            rv = asft_serial_send((unsigned char*) cpkt, n->pkt_len);
            if (rv < 0) {
                asft_error("Cannot send packet\n");
                return 1;
            }

            n->retry++;
        }


        got_response = false;
        timeout = asft_now() + retry_timeout * 1000;
        while(timeout > asft_now() && !got_response) {
            rv = asft_serial_receive((unsigned char**) &cresp, &rx_packet_len);
            if (rv < 0) {
                asft_error("Cannot receive response\n");
                return 1;
            }

            if (!cresp)
                continue;

            asft_debug_dump(cresp, rx_packet_len, "Received response");

            if (!n)
                continue;

            if (asft_packet_decrypt(&resp, cresp, rx_packet_len, &n->ikey)) {
                asft_debug("Response decryption failed\n");
                continue;
            }

            asft_debug_dump(resp, rx_packet_len, "Decrypted response");

            dh = &resp->base;
            rx_packet_number = be32toh(dh->packet_number);
            if (rx_packet_number != n->packet_number - 1) {
                asft_error("Node '%s' sent wrong packet number %u - expected %u\n", n->label, rx_packet_number, n->packet_number + 1);
                continue;
            }

            switch (dh->command)
            {
                case ASFT_RSP_ECDH_KEY:
                    process_resp_ecdh(n, &resp->ecdh, rx_packet_len);
                    break;
                default:
                    asft_error("Unknown command %x\n", dh->command);
            }
            got_response = true;
            n->retry = 0;
        };

        if (n && !got_response) {
            asft_debug("No response\n");
            if (n->retry >= retries) {
                asft_error("Node '%s' timeout\n", n->label);
                node_set_error(n);
            }
        }
    }

    return 0;
}
