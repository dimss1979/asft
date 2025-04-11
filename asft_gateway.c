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
    char *password;

    struct asft_key ikey_req;
    struct asft_key ikey_resp;
    struct asft_key skey_req;
    struct asft_key skey_resp;
    struct asft_ecdh *ecdh;
    bool have_skey;

    uint16_t packet_number;
    uint32_t ecdh_timestamp;

    uint32_t retry;
    uint64_t pause_until;
    bool error;
    bool got_response;

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
        if (asft_kdf(&n->ikey_req, n->password, strlen(n->password), asft_crypto_init_key_req)) {
            asft_error("Node '%s' initial key derivation failed\n", n->label);
            goto error;
        }
        if (asft_kdf(&n->ikey_resp, n->password, strlen(n->password), asft_crypto_init_key_resp)) {
            asft_error("Node '%s' initial key derivation failed\n", n->label);
            goto error;
        }
        n->blob_tx.auth_key = n->ikey_req.auth_blob;
        n->blob_rx.auth_key = n->ikey_resp.auth_blob;
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

static void process_resp_ecdh(struct node *n, struct asft_pkt_ecdh *resp, size_t resp_len)
{
    uint32_t rx_timestamp = be32toh(resp->timestamp);

    if (rx_timestamp == n->ecdh_timestamp) {
        n->got_response = true;
        n->retry = 0;
    } else {
        asft_error("Node '%s' invalid timestamp %u (expected %u)\n", n->label, rx_timestamp, n->ecdh_timestamp);
        return;
    }

    if (asft_ecdh_process(&n->ecdh, resp->public_key, &n->skey_req, &n->skey_resp))
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

static void process_resp_data(struct node *n, asft_pkt *resp, bool have_data)
{
    uint16_t rx_packet_number;
    if (have_data) {
        rx_packet_number = be16toh(resp->data.packet_number);
    } else {
        rx_packet_number = be16toh(resp->nodata.packet_number);
    }

    if (rx_packet_number == n->packet_number) {
        n->packet_number++;
        n->got_response = true;
        n->retry = 0;
    } else {
        asft_error("Node '%s' invalid packet number %u (expected %u)\n", n->label, rx_packet_number, n->packet_number);
        return;
    }

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

        struct asft_key *key_req = &n->ikey_req;
        struct asft_key *key_resp = &n->ikey_resp;
        asft_pkt pkt = {0}, cpkt = {0}, resp = {0};
        asft_pkt *cresp = NULL;
        size_t pkt_len = 0, rx_packet_len = 0, nonce_len = 0;


        if (n->have_skey && n->packet_number == 0) {
            asft_info("Node '%s' session key expired\n", n->label);
            n->have_skey = false;
        }

        if (n->have_skey) {
            key_req = &n->skey_req;
            key_resp = &n->skey_resp;

            asft_blob_tx_init(&n->blob_tx, n->download_dir);
            if (n->blob_tx.blob) {
                pkt_len = sizeof(pkt.data);
                pkt.data.packet_number = htobe16(n->packet_number);
                nonce_len = sizeof(pkt.data.packet_number);

                uint16_t block_idx = 0;
                asft_blob_tx_send(&n->blob_tx, &block_idx, pkt.data.data);
                pkt.data.block_idx = htobe16(block_idx);
                asft_blob_rx_get_ack(&n->blob_rx, &pkt.data.ack);
            } else {
                pkt_len = sizeof(pkt.nodata);
                pkt.nodata.packet_number = htobe16(n->packet_number);
                nonce_len = sizeof(pkt.nodata.packet_number);

                asft_blob_rx_get_ack(&n->blob_rx, &pkt.nodata.ack);
            }
        } else {
            asft_debug("Sending ECDH public key\n");
            n->ecdh_timestamp = (uint32_t) time(NULL);
            pkt.ecdh.timestamp = htobe32(n->ecdh_timestamp);
            pkt_len = sizeof(pkt.ecdh);
            nonce_len = sizeof(pkt.ecdh.timestamp);

            if (asft_ecdh_prepare(&n->ecdh, pkt.ecdh.public_key)) {
                asft_error("Node '%s' cannot prepare session key exchange\n", n->label);
            }
        }

        rv = asft_chaSIV_encrypt(&cpkt, &pkt, pkt_len, key_req, nonce_len);
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

            if (asft_chaSIV_decrypt(&resp, cresp, rx_packet_len, key_resp, nonce_len)) {
                asft_debug("Decryption failed\n");
                continue;
            }

            switch (rx_packet_len)
            {
                case ASFT_PKT_LEN_ECDH:
                    process_resp_ecdh(n, &resp.ecdh, rx_packet_len);
                    break;
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
