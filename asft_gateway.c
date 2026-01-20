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
#include <time.h>

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
    struct asft_crypto_ctx *crypto_ctx;

    uint32_t retry;
    uint64_t pause_until;
    bool error;
    bool got_response;

    struct asft_msg_tx msg_tx;
    struct asft_msg_rx msg_rx;
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
            asft_msg_tx_init(&n->msg_tx, n->download_dir);
            if (n->msg_tx.msg) {
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

static void process_resp_data(struct node *n, asft_pkt *resp, bool have_data)
{
    n->got_response = true;
    n->retry = 0;

    if (have_data) {
        asft_msg_rx_receive(&n->msg_rx, be16toh(resp->data.block_idx), resp->data.data, n->upload_dir);
    }
    uint8_t ack = resp->b.ack;

    asft_msg_tx_ack(&n->msg_tx, ack);

    asft_msg_tx_init(&n->msg_tx, n->download_dir);
    if (!n->msg_tx.msg && !have_data) {
        proceed_idle(n);
    }
}

int asft_gateway_loop()
{
    int rv;
    struct node *n = NULL;
    uint64_t timeout;

    if (nodes_init()) {
        asft_error("Initialization failed\n");
        return 1;
    }

    while(1)
    {
        unpause_for_download();
        n = node_pick_next(n);

        if (!n) {
            sleep(1);
            continue;
        }

        asft_debug("Picked node '%s'\n", n->label);

        asft_pkt pkt = {0}, cpkt = {0}, resp = {0};
        asft_pkt *cresp = NULL;
        size_t pkt_len = 0, rx_packet_len = 0;

        asft_msg_tx_init(&n->msg_tx, n->download_dir);
        if (n->msg_tx.msg) {
            pkt_len = sizeof(pkt.data);

            uint16_t block_idx = 0;
            asft_msg_tx_send(&n->msg_tx, &block_idx, pkt.data.data);
            pkt.data.block_idx = htobe16(block_idx);
        } else {
            pkt_len = sizeof(pkt.nodata);
        }
        asft_msg_rx_get_ack(&n->msg_rx, &pkt.b.ack);

        rv = asft_encrypt_req(n->crypto_ctx, &cpkt, &pkt, pkt_len);
        if (rv) {
            asft_error("Node '%s' cannot encrypt packet\n", n->label);
            return 1;
        }

        asft_debug("Sending request %u bytes\n", pkt_len);

        rv = asft_serial_send((unsigned char*) &cpkt, pkt_len);
        if (rv < 0) {
            asft_error("Cannot send request\n");
            return 1;
        }
        n->retry++;

        n->got_response = false;
        timeout = asft_now() + retry_timeout * 1000;
        while(timeout > asft_now() && !n->got_response) {
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

            if (asft_decrypt_resp(n->crypto_ctx, &resp, cresp, rx_packet_len)) {
                asft_debug("Decryption failed\n");
                continue;
            }

            switch (rx_packet_len)
            {
                case ASFT_PKT_LEN_NODATA:
                    process_resp_data(n, &resp, false);
                    break;
                case ASFT_PKT_LEN_DATA:
                    process_resp_data(n, &resp, true);
                    break;
                default:
                    asft_error("Node '%s' invalid response length %u bytes\n", n->label, rx_packet_len);
            }
        };

        if (!n->got_response) {
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

    new->crypto_ctx = asft_crypto_ctx_init(password);
    if (!new->crypto_ctx)
        goto error;

    new->msg_tx.crypto_ctx = new->crypto_ctx;
    new->msg_rx.crypto_ctx = new->crypto_ctx;
    new->next = node_first;
    node_first = new;
    node_cnt++;

    return 0;

error:

    if (new) {
        free(new->label);
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
