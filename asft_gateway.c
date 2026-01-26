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

    uint64_t pause_until;
    uint32_t backoff_time;
    bool ready;

    struct asft_msg_tx msg_tx;
    struct asft_msg_rx msg_rx;
    char *upload_dir;
    char *download_dir;
};

static struct node *node_first = NULL;
static unsigned int node_cnt = 0;

static int retry_timeout = 5;
static uint32_t backoff_time_max = 60;

static void apply_backoff(struct node *n)
{
    if (n->backoff_time == 0) {
        n->backoff_time = 1;
    } else {
        n->backoff_time *= 2;
        if (n->backoff_time > backoff_time_max) {
            n->backoff_time = backoff_time_max;
        }
    }
    n->pause_until = asft_now() + n->backoff_time * 1000;
}

static void reset_backoff(struct node *n)
{
    n->backoff_time = 0;
    n->pause_until = 0;
}

static void unpause_for_download()
{
    uint64_t now = asft_now();
    struct node *n = node_first;

    while (n)
    {
        if (n->pause_until > now && !n->msg_tx.msg && n->ready) {
            asft_msg_tx_init(&n->msg_tx, n->download_dir);
            if (n->msg_tx.msg) {
                reset_backoff(n);
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

static void process_resp_data(struct node *n, asft_pkt *resp, struct asft_pkt_flags *resp_flags, bool have_data)
{
    if (have_data) {
        if (asft_msg_rx_receive(&n->msg_rx, resp_flags->seq, resp->data.data, n->upload_dir)) {
            asft_error("Error while processing data packet from '%s'\n", n->label);

            asft_msg_tx_cancel(&n->msg_tx);
            asft_msg_rx_cancel(&n->msg_rx);
            n->ready = false;
            return;
        }
    }

    asft_msg_tx_ack(&n->msg_tx, resp_flags->ack);
    asft_msg_tx_init(&n->msg_tx, n->download_dir);
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
        bool keep_talking = false;
        struct asft_pkt_flags req_flags = {0};

        if (n->ready) {
            asft_msg_tx_init(&n->msg_tx, n->download_dir);
            if (n->msg_tx.msg) {
                pkt_len = sizeof(pkt.data);
                req_flags.cmd = ASFT_CMD_DATA;

                asft_msg_tx_send(&n->msg_tx, &req_flags.seq, pkt.data.data);
                keep_talking = true;
            } else {
                pkt_len = sizeof(pkt.nodata);
                req_flags.cmd = ASFT_CMD_NODATA;
            }
            asft_msg_rx_get_ack(&n->msg_rx, &req_flags.ack);
        } else {
            asft_debug("Sending reset to '%s'\n", n->label);
            pkt_len = sizeof(pkt.nodata);
            req_flags.cmd = ASFT_CMD_RESET;
            keep_talking = true;
        }

        pkt.b.flags = asft_pkt_flags_encode(&req_flags);

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

        bool got_response = false;
        timeout = asft_now() + retry_timeout * 1000;
        while(timeout > asft_now() && !got_response) {
            rv = asft_serial_receive((unsigned char**) &cresp, &rx_packet_len);
            if (rv < 0) {
                asft_error("Cannot receive response\n");
                return 1;
            }

            if (!cresp || rx_packet_len < sizeof(struct asft_pkt_base))
                continue;

            asft_debug("Received %u bytes\n", rx_packet_len);

            if (asft_decrypt_resp(n->crypto_ctx, &resp, cresp, rx_packet_len)) {
                asft_debug("Decryption failed\n");
                continue;
            }

            struct asft_pkt_flags resp_flags;
            asft_pkt_flags_decode(&resp_flags, resp.b.flags);
            got_response = true;

            switch (rx_packet_len)
            {
                case ASFT_PKT_LEN_NODATA:
                    switch (resp_flags.cmd) {
                        case ASFT_CMD_READY:
                            asft_debug("Node '%s' is ready\n", n->label);
                            asft_crypto_set_session_timestamp(n->crypto_ctx);
                            asft_msg_tx_cancel(&n->msg_tx);
                            asft_msg_rx_cancel(&n->msg_rx);
                            n->ready = true;
                            keep_talking = true;
                            break;
                        case ASFT_CMD_NOT_READY:
                            asft_debug("Node '%s' is not ready\n", n->label);
                            asft_msg_tx_cancel(&n->msg_tx);
                            asft_msg_rx_cancel(&n->msg_rx);
                            n->ready = false;
                            keep_talking = true;
                            break;
                        case ASFT_CMD_NODATA:
                            process_resp_data(n, &resp, &resp_flags, false);
                            break;
                        default:
                            got_response = false;
                    }
                    break;
                case ASFT_PKT_LEN_DATA:
                    switch (resp_flags.cmd) {
                        case ASFT_CMD_DATA:
                            process_resp_data(n, &resp, &resp_flags, true);
                            keep_talking = true;
                            break;
                        default:
                            got_response = false;
                    }
                    break;
                default:
                    got_response = false;
            }

            if (!got_response)
                asft_error("Node '%s' invalid response length %u command %u\n", n->label, rx_packet_len, resp_flags.cmd);
        };

        if (!got_response)
            asft_debug("No response\n");

        if (!keep_talking || !got_response) {
            apply_backoff(n);
        } else {
            reset_backoff(n);
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

void asft_gateway_set_retry_timeout(int new_timeout)
{
    retry_timeout = new_timeout;
}

void asft_gateway_set_backoff_time_max(uint32_t new_backoff_time_max)
{
    backoff_time_max = new_backoff_time_max;
}
