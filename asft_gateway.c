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
    struct asft_key *ckey;

    uint32_t packet_number;
    enum asft_command cmd;
    unsigned int retry;
    uint64_t pause_until;
    bool had_file;

    asft_packet pkt;
    unsigned int pkt_len;

    struct asft_file_ctx file;
    char *upload_dir;
    char *download_dir;
};

static struct node *node_first = NULL;
static unsigned int node_cnt = 0;

static int retries = 5;
static int retry_timeout = 5;
static int pause_idle = 10;
static int pause_error = 10;

static void proceed_ecdh_key(struct node *n)
{
    n->cmd = ASFT_REQ_ECDH_KEY;
    n->pkt_len = sizeof(n->pkt.ecdh);
    n->retry = 0;
    getrandom(&n->packet_number, sizeof(n->packet_number), 0);
    n->ckey = &n->ikey;
    if (asft_ecdh_prepare(&n->ecdh, n->pkt.ecdh.public_key)) {
        asft_error("Node '%s' cannot prepare session key exchange\n", n->label);
    }
}

static void proceed_error(struct node *n)
{
    proceed_ecdh_key(n);
    n->pause_until = 1000 * pause_error + asft_now();
}

static void proceed_get_file(struct node *n)
{
    n->cmd = ASFT_REQ_GET_FILE;
    n->pkt_len = sizeof(n->pkt.base);
    n->retry = 0;
    n->had_file = false;
}

static void proceed_idle(struct node *n)
{
    proceed_get_file(n);
    n->pause_until = 1000 * pause_idle + asft_now();
}

static void proceed_get_block(struct node *n)
{
    n->cmd = ASFT_REQ_GET_BLOCK;
    n->pkt_len = sizeof(n->pkt.get_block_req);
    n->pkt.get_block_req.block = htobe32(n->file.block);
    n->retry = 0;
}

static void proceed_upload_complete(struct node *n)
{
    n->cmd = ASFT_REQ_UPLOAD_COMPLETE;
    n->pkt_len = sizeof(n->pkt.base);
    n->retry = 0;
}

static void proceed_put_file(struct node *n)
{
    struct asft_file_ctx *d = &n->file;

    if (asft_file_src_open(n->download_dir, d))
        goto error;

    if (!d->name) {
        asft_debug("No file to download\n");
        if (n->had_file)
            proceed_get_file(n);
        else
            proceed_idle(n);
        return;
    }

    n->cmd = ASFT_REQ_PUT_FILE;
    n->retry = 0;
    n->pkt.file_info.size = htobe32(d->size);
    memcpy(n->pkt.file_info.name, d->name, d->name_len);
    n->pkt_len = sizeof(n->pkt.file_info) - sizeof(n->pkt.file_info.name) + d->name_len;
    n->had_file = true;
    return;

error:

    asft_error("Node '%s' cannot proceed to download\n", n->label);
    proceed_error(n);
    return;
}

static void proceed_put_block(struct node *n)
{
    struct asft_file_ctx *d = &n->file;
    unsigned int data_len = d->left > ASFT_BLOCK_LEN ? ASFT_BLOCK_LEN : d->left;

    if (asft_file_src_read(d, n->pkt.put_block_req.data, data_len))
        goto error;

    n->cmd = ASFT_REQ_PUT_BLOCK;
    n->retry = 0;
    n->pkt.put_block_req.block = htobe32(d->block);
    n->pkt_len = sizeof(n->pkt.put_block_req) - sizeof(n->pkt.put_block_req.data) + data_len;
    d->block++;
    d->left -= data_len;
    return;

error:

    asft_error("Node '%s' cannot read download block\n", n->label);
    proceed_error(n);
    return;
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
        asft_file_ctx_init(&n->file);
        if (asprintf(&n->upload_dir, "from_%s", n->label) < 0)
            goto error;
        if (asprintf(&n->download_dir, "to_%s", n->label) < 0)
            goto error;
        proceed_ecdh_key(n);

        n = n->next;
    }

    return 0;

error:

    return -1;
}

static void process_resp_ecdh(struct node *n, struct asft_cmd_ecdh *resp, size_t resp_len)
{
    if (resp_len != sizeof(*resp))
        goto error;

    if (n->cmd != ASFT_REQ_ECDH_KEY)
        goto error;

    if (asft_ecdh_process(&n->ecdh, resp->public_key, &n->skey))
        goto error;

    n->packet_number = 0;
    n->ckey = &n->skey;
    proceed_get_file(n);

    asft_info("Node '%s' session key exchange complete\n", n->label);

    return;

error:

    asft_error("Node '%s' session key exchange failed\n", n->label);
    proceed_error(n);

    return;
}

static void process_resp_get_file_ack(struct node *n, struct asft_cmd_file_info *resp, size_t resp_len)
{
    unsigned int size_max = sizeof(*resp);
    unsigned int size_min = size_max - sizeof(resp->name) + 1;
    unsigned int name_len = resp_len - size_min + 1;
    struct asft_file_ctx *u = &n->file;

    if (resp_len < size_min || resp_len > size_max)
        goto error;

    if (n->cmd != ASFT_REQ_GET_FILE)
        goto error;

    asft_file_ctx_reset(u);
    u->size = be32toh(resp->size);
    u->left = u->size;
    u->name = strndup((char *) resp->name, name_len);
    if (!u->name)
        goto error;

    if (asft_file_name_validate(u->name, name_len))
        goto error;

    if (asft_file_dst_open(n->upload_dir, u))
        goto error;

    asft_info("Node '%s' uploading file '%s' (%u bytes)\n", n->label, u->name, u->size);

    if (u->left) {
        proceed_get_block(n);
    } else {
        if (asft_file_dst_complete(u))
            goto error;

        proceed_upload_complete(n);
    }
    n->had_file = true;

    return;

error:

    asft_error("Node '%s' ASFT_RSP_GET_FILE_ACK error\n", n->label);
    proceed_error(n);
    asft_file_ctx_reset(u);

    return;
}

static void process_resp_get_file_nak(struct node *n, struct asft_base_hdr *resp, size_t resp_len)
{
    if (resp_len != sizeof(*resp))
        goto error;

    if (n->cmd != ASFT_REQ_GET_FILE)
        goto error;

    asft_debug("Node has no file to upload\n");
    proceed_put_file(n);

    return;

error:

    asft_error("Node '%s' invalid ASFT_RSP_GET_FILE_NAK response\n", n->label);
    proceed_error(n);

    return;
}

static void process_resp_get_block(struct node *n, struct asft_cmd_get_block_rsp *resp, size_t resp_len)
{
    unsigned int size_max = sizeof(*resp);
    unsigned int size_min = size_max - sizeof(resp->data) + 1;
    unsigned int data_len = resp_len - size_min + 1;
    struct asft_file_ctx *u = &n->file;

    if (resp_len < size_min || resp_len > size_max)
        goto error;

    if (n->cmd != ASFT_REQ_GET_BLOCK)
        goto error;

    if (data_len > u->left)
        goto error;

    asft_debug("Uploaded %u bytes\n", data_len);

    if (asft_file_dst_write(u, resp->data, data_len))
        goto error;

    u->left -= data_len;
    u->block++;

    if (u->left) {
        proceed_get_block(n);
        return;
    }

    if (asft_file_dst_complete(u))
        goto error;

    proceed_upload_complete(n);

    return;

error:

    asft_error("Node '%s' ASFT_RSP_GET_BLOCK error\n", n->label);
    asft_file_ctx_reset(u);
    proceed_error(n);

    return;
}

static void process_resp_upload_complete(struct node *n, struct asft_base_hdr *resp, size_t resp_len)
{
    if (resp_len != sizeof(*resp))
        goto error;

    if (n->cmd != ASFT_REQ_UPLOAD_COMPLETE)
        goto error;

    asft_debug("Upload complete ack\n");
    proceed_put_file(n);

    return;

error:

    asft_error("Node '%s' ASFT_RSP_UPLOAD_COMPLETE error\n", n->label);
    proceed_error(n);

    return;
}

static void process_resp_put_file(struct node *n, struct asft_base_hdr *resp, size_t resp_len)
{
    if (resp_len != sizeof(*resp))
        goto error;

    if (n->cmd != ASFT_REQ_PUT_FILE)
        goto error;

    asft_debug("Put file ack\n");
    if (n->file.left) {
        proceed_put_block(n);
    } else {
        if (asft_file_src_complete(&n->file))
            goto error;
        asft_info("Node '%s' download complete\n", n->label);
        if (n->had_file)
            proceed_get_file(n);
        else
            proceed_idle(n);
    }

    return;

error:

    asft_error("Node '%s' ASFT_RSP_PUT_FILE error\n", n->label);
    proceed_error(n);

    return;
}

static void process_resp_put_block(struct node *n, struct asft_base_hdr *resp, size_t resp_len)
{
    if (resp_len != sizeof(*resp))
        goto error;

    if (n->cmd != ASFT_REQ_PUT_BLOCK)
        goto error;

    asft_debug("Put block ack\n");
    if (n->file.left) {
        proceed_put_block(n);
    } else {
        if (asft_file_src_complete(&n->file))
            goto error;
        asft_info("Node '%s' download complete\n", n->label);
        if (n->had_file)
            proceed_get_file(n);
        else
            proceed_idle(n);
    }

    return;

error:

    asft_error("Node '%s' ASFT_RSP_PUT_BLOCK error\n", n->label);
    proceed_error(n);

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
    asft_debug("Nodes initialized\n");

    while(1)
    {
        n = node_pick_next(n);

        if (n) {
            asft_debug("Picked node '%s' retry %u\n", n->label, n->retry);
            n->pkt.base.packet_number = htobe32(n->packet_number);
            n->packet_number += 2;

            if (!n->retry) {
                n->pkt.base.command = n->cmd;

                switch(n->cmd)
                {
                    case ASFT_REQ_ECDH_KEY:
                        asft_info("Node '%s' session key exchange\n", n->label);
                        break;
                    case ASFT_REQ_GET_FILE:
                        asft_debug("Node '%s' get file\n", n->label);
                        break;
                    case ASFT_REQ_GET_BLOCK:
                        asft_debug("Node '%s' get block %u\n", n->label, n->file.block);
                        break;
                    case ASFT_REQ_UPLOAD_COMPLETE:
                        asft_info("Node '%s' upload complete\n", n->label);
                        break;
                    case ASFT_REQ_PUT_FILE:
                        asft_info("Node '%s' downloading file '%s' (%u bytes)\n", n->label, n->file.name, n->file.size);
                        break;
                    case ASFT_REQ_PUT_BLOCK:
                        asft_debug("Node '%s' put block %u\n", n->label, n->file.block - 1);
                        break;
                    default:
                        asft_error("Node '%s' invalid command %i\n", n->label, n->cmd);
                        return 1;
                }
            }

            rv = asft_packet_encrypt(&cpkt, &n->pkt, n->pkt_len, n->ckey);
            if (rv || !cpkt) {
                asft_error("Node '%s' cannot encrypt packet\n", n->label);
                return 1;
            }

            asft_debug("Sending request %u bytes\n", n->pkt_len);

            rv = asft_serial_send((unsigned char*) cpkt, n->pkt_len);
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

            if (asft_packet_decrypt(&resp, cresp, rx_packet_len, n->ckey)) {
                asft_debug("Decryption failed\n");
                continue;
            }

            dh = &resp->base;
            rx_packet_number = be32toh(dh->packet_number);
            if (rx_packet_number != n->packet_number - 1) {
                asft_error("Node '%s' packet number %u, expected %u\n", n->label, rx_packet_number, n->packet_number + 1);
                continue;
            }

            switch (dh->command)
            {
                case ASFT_RSP_ECDH_KEY:
                    process_resp_ecdh(n, &resp->ecdh, rx_packet_len);
                    break;
                case ASFT_RSP_GET_FILE_ACK:
                    process_resp_get_file_ack(n, &resp->file_info, rx_packet_len);
                    break;
                case ASFT_RSP_GET_FILE_NAK:
                    process_resp_get_file_nak(n, &resp->base, rx_packet_len);
                    break;
                case ASFT_RSP_GET_BLOCK:
                    process_resp_get_block(n, &resp->get_block_rsp, rx_packet_len);
                    break;
                case ASFT_RSP_UPLOAD_COMPLETE:
                    process_resp_upload_complete(n, &resp->base, rx_packet_len);
                    break;
                case ASFT_RSP_PUT_FILE:
                    process_resp_put_file(n, &resp->base, rx_packet_len);
                    break;
                case ASFT_RSP_PUT_BLOCK:
                    process_resp_put_block(n, &resp->base, rx_packet_len);
                    break;
                case ASFT_RSP_ERROR:
                    asft_info("Node '%s' indicating error\n", n->label);
                    proceed_error(n);
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
    struct node *new;

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
