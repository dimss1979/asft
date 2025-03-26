#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif /*_GNU_SOURCE*/

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
#include "asft_file.h"

#include "asft_gateway.h"

struct node
{
    struct node *next;
    char *label;
    char *password;

    struct asft_key ikey;
    struct asft_key skey;
    struct asft_ecdh *ecdh;
    bool have_skey;

    uint32_t packet_number;
    uint32_t retry;
    uint64_t pause_until;
    bool error;

    struct asft_blob_tx blob_tx;
    struct asft_blob_rx blob_rx;
    char *upload_dir;
    char *download_dir;
};

static struct node *node_first = NULL;
static unsigned int node_cnt = 0;

static int retries = 5;
static int retry_timeout = 5;
static int pause_idle = 10;
static int pause_error = 10;

static void proceed_error(struct node *n)
{
    n->pause_until = 1000 * pause_error + asft_now();
    n->error = true;
    n->retry = 0;
    n->have_skey = 0;
}

static void proceed_idle(struct node *n)
{
    n->pause_until = 1000 * pause_idle + asft_now();
    n->error = false;
    n->retry = 0;
}

static void unpause_for_download()
{
    uint64_t now = asft_now();
    struct node *n = node_first;

    while (n)
    {
        if (n->pause_until > now && !n->error) {
            asft_blob_tx_init(&n->blob_tx, n->download_dir);
            if (n->blob_tx.blob) {
                n->pause_until = 0;
            }
        }

        n = n->next;
    }
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

        if (n->pause_until <= now) {
            n->error = false;
            return n;
        }

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
        if (asft_kdf(&n->ikey, n->password, strlen(n->password))) {
            asft_error("Node '%s' initial key derivation failed\n", n->label);
            goto error;
        }
        n->blob_tx.auth_key = n->ikey.auth_blob;
        n->blob_rx.auth_key = n->ikey.auth_blob;
        if (asprintf(&n->upload_dir, "from_%s", n->label) < 0)
            goto error;
        if (asprintf(&n->download_dir, "to_%s", n->label) < 0)
            goto error;

        n = n->next;
    }

    return 0;

error:

    return -1;
}

static void process_resp_ecdh(struct node *n, struct asft_cmd_ecdh *resp, size_t resp_len)
{
    if (asft_ecdh_process(&n->ecdh, resp->public_key, &n->skey))
        goto error;

    n->packet_number = 1;
    n->have_skey = true;

    asft_info("Node '%s' session key exchange complete\n", n->label);

    return;

error:

    asft_error("Node '%s' session key exchange error\n", n->label);
    proceed_error(n);

    return;
}

static void process_resp_data(struct node *n, asft_packet *resp, bool have_data)
{
    uint8_t ack;
    if (have_data) {
        asft_blob_rx_receive(&n->blob_rx, be16toh(resp->data.block_idx), resp->data.data, n->upload_dir);
        ack = resp->data.ack;
    } else {
        ack = resp->nodata.ack;
    }
    asft_blob_tx_ack(&n->blob_tx, ack);

    asft_blob_tx_init(&n->blob_tx, n->download_dir);
    if (!n->blob_tx.blob && !have_data) {
        proceed_idle(n);
    }

    n->packet_number++;
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
    asft_debug("Nodes initialized\n");

    while(1)
    {
        unpause_for_download();
        n = node_pick_next(n);
        struct asft_key *ckey = &n->ikey;

        if (n) {
            asft_debug("Picked node '%s' retry %u\n", n->label, n->retry);

            asft_packet pkt = {0};
            size_t pkt_len = 0;

            if (n->have_skey) {
                ckey = &n->skey;
                pkt.base.packet_number = htobe32(n->packet_number);
                asft_blob_tx_init(&n->blob_tx, n->download_dir);
                if (n->blob_tx.blob) {
                    pkt.base.command = ASFT_REQ_DATA;
                    pkt_len = sizeof(pkt.data);

                    uint16_t block_idx = 0;
                    asft_blob_tx_send(&n->blob_tx, &block_idx, pkt.data.data);
                    pkt.data.block_idx = htobe16(block_idx);
                    asft_blob_rx_get_ack(&n->blob_rx, &pkt.data.ack);
                } else {
                    pkt.base.command = ASFT_REQ_NODATA;
                    pkt_len = sizeof(pkt.nodata);

                    asft_blob_rx_get_ack(&n->blob_rx, &pkt.nodata.ack);
                }
            } else {
                asft_debug("Sending ECDH public key\n");
                getrandom(&n->packet_number, sizeof(n->packet_number), 0);
                pkt.base.packet_number = htobe32(n->packet_number);
                pkt.base.command = ASFT_REQ_ECDH_KEY;
                pkt_len = sizeof(pkt.ecdh);

                if (asft_ecdh_prepare(&n->ecdh, pkt.ecdh.public_key)) {
                    asft_error("Node '%s' cannot prepare session key exchange\n", n->label);
                }
            }

            rv = asft_packet_encrypt(&cpkt, &pkt, pkt_len, ckey);
            if (rv || !cpkt) {
                asft_error("Node '%s' cannot encrypt packet\n", n->label);
                return 1;
            }

            asft_debug("Sending request %u bytes\n", pkt_len);

            rv = asft_serial_send((unsigned char*) cpkt, pkt_len);
            if (rv < 0) {
                asft_error("Cannot send request\n");
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

            asft_debug("Received %u bytes\n", rx_packet_len);

            if (!n)
                continue;

            if (asft_packet_decrypt(&resp, cresp, rx_packet_len, ckey)) {
                asft_debug("Decryption failed\n");
                continue;
            }

            dh = &resp->base;
            rx_packet_number = be32toh(dh->packet_number);
            if (rx_packet_number != n->packet_number) {
                asft_error("Node '%s' packet number %u, expected %u\n", n->label, rx_packet_number, n->packet_number);
                continue;
            }

            switch (dh->command)
            {
                case ASFT_RSP_ECDH_KEY:
                    process_resp_ecdh(n, &resp->ecdh, rx_packet_len);
                    break;
                case ASFT_RSP_NODATA:
                    process_resp_data(n, resp, false);
                    break;
                case ASFT_RSP_DATA:
                    process_resp_data(n, resp, true);
                    break;
                default:
                    asft_error("Node '%s' invalid response %u\n", n->label, dh->command);
                    proceed_error(n);
            }
            got_response = true;
            n->retry = 0;
        };

        if (n && !got_response) {
            asft_debug("No response\n");
            if (n->retry >= retries) {
                asft_error("Node '%s' timeout\n", n->label);
                proceed_error(n);
            }
        }
    }

    return 0;
}

int asft_gateway_add_node(char *label, char *password)
{
    struct node *new = NULL;

    if (strchr(label, '/')) {
        asft_error("Invalid label - contains slash\n");
        goto error;
    }

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
        free(new->label);
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
