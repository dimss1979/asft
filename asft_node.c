#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif /*_GNU_SOURCE*/

#include <stdio.h>
#include <string.h>
#include <sys/random.h>
#include <endian.h>
#include <stdlib.h>

#include "asft_proto.h"
#include "asft_crypto.h"
#include "asft_serial.h"
#include "asft_misc.h"
#include "asft_file.h"

#include "asft_node.h"

static struct gateway
{
    char *label;
    char *password;

    struct asft_key ikey;
    struct asft_key tkey;
    struct asft_key skey;
    struct asft_ecdh *ecdh;

    uint32_t last_packet_number;

    struct asft_file_ctx file;
    char *upload_dir;
    char *download_dir;
} gw = { 0 };

static int gateway_init()
{
    if (!gw.label || !gw.password) {
        asft_error("Gateway not specified\n");
        goto error;
    }
    if(asft_kdf(&gw.ikey, gw.password)) {
        asft_error("Gateway initial key derivation failed\n");
        goto error;
    };
    getrandom(&gw.skey, sizeof(gw.skey), 0);
    asft_file_init(&gw.file);
    if (asprintf(&gw.upload_dir, "to_%s", gw.label) < 0)
        goto error;
    if (asprintf(&gw.download_dir, "from_%s", gw.label) < 0)
        goto error;

    return 0;

error:

    return -1;
}

static void process_error(asft_packet *resp, size_t *resp_len)
{
    asft_error("Indicate error to gateway\n");

    resp->base.command = ASFT_RSP_ERROR;
    *resp_len = sizeof(resp->base);

    return;
}

static void process_req_ecdh(asft_packet *req, size_t req_len, asft_packet *resp, size_t *resp_len)
{
    if (req_len != sizeof(req->ecdh))
        goto error;

    if (asft_ecdh_prepare(&gw.ecdh, resp->ecdh.public_key))
        goto error;

    if (asft_ecdh_process(&gw.ecdh, req->ecdh.public_key, &gw.tkey))
        goto error;

    resp->base.command = ASFT_RSP_ECDH_KEY;
    *resp_len = sizeof(resp->ecdh);

    asft_info("Session key exchange complete\n");

    return;

error:

    asft_error("Session key exchange failed\n");
    process_error(resp, resp_len);

    return;
}

static void process_req_get_file(asft_packet *req, size_t req_len, asft_packet *resp, size_t *resp_len)
{
    struct asft_file_ctx *u = &gw.file;

    if (req_len != sizeof(req->base))
        goto error;

    if (asft_file_src_open(u, gw.upload_dir))
        goto error;

    if (!u->name) {
        resp->base.command = ASFT_RSP_GET_FILE_NAK;
        *resp_len = sizeof(resp->base);

        asft_debug("No file to upload\n");

        return;
    }

    u->block = 0;
    resp->base.command = ASFT_RSP_GET_FILE_ACK;
    resp->file_info.size = htobe32(u->size);
    memcpy(resp->file_info.name, u->name, u->name_len);
    *resp_len = sizeof(resp->file_info) - sizeof(resp->file_info.name) + u->name_len;

    asft_info("Uploading file '%s' (%u bytes)\n", u->name, u->size);

    return;

error:

    asft_error("File upload request failed\n");
    process_error(resp, resp_len);

    return;
}

static void process_req_get_block(asft_packet *req, size_t req_len, asft_packet *resp, size_t *resp_len)
{
    struct asft_file_ctx *u = &gw.file;
    unsigned int block = be32toh(req->get_block_req.block);

    if (req_len != sizeof(req->get_block_req))
        goto error;

    if (block != u->block) {
        if (!u->left)
            goto error;

        u->data_len = u->left > ASFT_BLOCK_LEN ? ASFT_BLOCK_LEN : u->left;
        if (asft_file_src_read(u, u->data, u->data_len))
            goto error;

        u->block = block;
        u->left -= u->data_len;
    }

    resp->base.command = ASFT_RSP_GET_BLOCK;
    memcpy(&resp->get_block_rsp.data, u->data, u->data_len);
    *resp_len = sizeof(resp->get_block_rsp) - sizeof(resp->get_block_rsp.data) + u->data_len;

    asft_debug("Uploading block %u/%u (%u bytes)\n", block, u->blocks, u->data_len);

    return;

error:

    asft_error("Block upload request failed\n");
    process_error(resp, resp_len);

    return;
}

static void process_req_upload_complete(asft_packet *req, size_t req_len, asft_packet *resp, size_t *resp_len)
{
    if (req_len != sizeof(req->base))
        goto error;

    if (asft_file_src_complete(&gw.file))
        goto error;

    resp->base.command = ASFT_RSP_UPLOAD_COMPLETE;
    *resp_len = sizeof(resp->base);

    asft_info("Upload complete\n");

    return;

error:

    asft_error("Upload complete request failed\n");
    process_error(resp, resp_len);

    return;
}

static void process_req_put_file(asft_packet *req, size_t req_len, asft_packet *resp, size_t *resp_len)
{
    unsigned int size_max = sizeof(req->file_info);
    unsigned int size_min = size_max - sizeof(req->file_info.name) + 1;
    unsigned int name_len = req_len - size_min + 1;
    struct asft_file_ctx *d = &gw.file;

    if (req_len < size_min || req_len > size_max)
        goto error;

    if (asft_file_dst_open(d, gw.download_dir, (char *) req->file_info.name, name_len, be32toh(req->file_info.size)))
        goto error;

    asft_info("Downloading file '%s' (%u bytes)\n", d->name, d->size);

    if (!d->left) {
        if (asft_file_dst_complete(d))
            goto error;
        asft_info("Download complete\n");
    }

    d->block = 0;
    resp->base.command = ASFT_RSP_PUT_FILE;
    *resp_len = sizeof(resp->base);

    return;

error:

    asft_error("File download request failed\n");
    process_error(resp, resp_len);

    return;
}

static void process_req_put_block(asft_packet *req, size_t req_len, asft_packet *resp, size_t *resp_len)
{
    unsigned int size_max = sizeof(req->put_block_req);
    unsigned int size_min = size_max - sizeof(req->put_block_req.data) + 1;
    unsigned int data_len = req_len - size_min + 1;
    struct asft_file_ctx *d = &gw.file;
    unsigned int block = be32toh(req->put_block_req.block);

    if (req_len < size_min || req_len > size_max)
        goto error;

    if (block != d->block) {
        if (data_len > d->left)
            goto error;

        asft_debug("Downloading block %u/%u (%u bytes)\n", block, d->blocks, data_len);

        if (asft_file_dst_write(d, req->put_block_req.data, data_len))
            goto error;

        d->block = block;
        d->left -= data_len;

        if (!d->left) {
            if (asft_file_dst_complete(d))
                goto error;
            asft_info("Download complete\n");
        }
    } else {
        asft_debug("Received duplicate block\n");
    }

    resp->base.command = ASFT_RSP_PUT_BLOCK;
    *resp_len = sizeof(resp->base);

    return;

error:

    asft_error("Block download request failed\n");
    process_error(resp, resp_len);

    return;
}

int asft_node_loop()
{
    if (gateway_init()) {
        asft_error("Gateway initialization failed\n");
        return 1;
    }
    asft_debug("Gateway initialized\n");

    while (1) {
        int rv = 0;
        asft_packet *pkt = NULL;
        asft_packet *cpkt = NULL;
        size_t pkt_len = 0;
        struct asft_base_hdr *dh;
        asft_packet resp, *cresp = NULL;
        size_t resp_len = 0;
        enum {D_NKEY, D_IKEY, D_TKEY, D_SKEY} decryption_key = D_NKEY;
        uint32_t rx_packet_number;
        struct asft_key *ckey = &gw.skey;

        rv = asft_serial_receive((unsigned char**) &cpkt, &pkt_len);
        if (rv < 0) {
            asft_error("Cannot receive packet\n");
            return 1;
        }
        if (!rv || !cpkt || !pkt_len) {
            continue;
        }

        asft_debug("Received %u bytes\n", pkt_len);

        rv = asft_packet_decrypt(&pkt, cpkt, pkt_len, &gw.skey);
        if (!rv && pkt) {
            decryption_key = D_SKEY;
            goto decrypted;
        }
        rv = asft_packet_decrypt(&pkt, cpkt, pkt_len, &gw.ikey);
        if (!rv && pkt) {
            decryption_key = D_IKEY;
            goto decrypted;
        }
        rv = asft_packet_decrypt(&pkt, cpkt, pkt_len, &gw.tkey);
        if (!rv && pkt) {
            decryption_key = D_TKEY;
            goto decrypted;
        }

        asft_debug("Decryption failed\n");
        continue;

decrypted:

        dh = &pkt->base;

        if (dh->command == ASFT_REQ_ECDH_KEY && decryption_key != D_IKEY) {
            asft_error("Key exchange must be encrypted with initial key\n");
            continue;
        } else if (dh->command != ASFT_REQ_GET_FILE && decryption_key == D_TKEY) {
            asft_error("Command %u is encrypted with temporary key\n", dh->command);
            continue;
        }

        rx_packet_number = be32toh(pkt->base.packet_number);
        if (decryption_key == D_SKEY && rx_packet_number <= gw.last_packet_number) {
            asft_error("Packet number %u, last was %u\n", rx_packet_number, gw.last_packet_number);
            continue;
        }
        if (decryption_key == D_TKEY && rx_packet_number) {
            asft_error("Packet number %u, must be 0\n", rx_packet_number);
            continue;
        }
        if (decryption_key != D_IKEY) {
            gw.last_packet_number = rx_packet_number;
        }

        if (decryption_key == D_TKEY)
            memcpy(&gw.skey, &gw.tkey, sizeof(gw.skey));

        switch (dh->command)
        {
            case ASFT_REQ_ECDH_KEY:
                process_req_ecdh(pkt, pkt_len, &resp, &resp_len);
                ckey = &gw.ikey;
                break;
            case ASFT_REQ_GET_FILE:
                process_req_get_file(pkt, pkt_len, &resp, &resp_len);
                break;
            case ASFT_REQ_GET_BLOCK:
                process_req_get_block(pkt, pkt_len, &resp, &resp_len);
                break;
            case ASFT_REQ_UPLOAD_COMPLETE:
                process_req_upload_complete(pkt, pkt_len, &resp, &resp_len);
                break;
            case ASFT_REQ_PUT_FILE:
                process_req_put_file(pkt, pkt_len, &resp, &resp_len);
                break;
            case ASFT_REQ_PUT_BLOCK:
                process_req_put_block(pkt, pkt_len, &resp, &resp_len);
                break;
            default:
                asft_error("Unknown command %u\n", dh->command);
                process_error(&resp, &resp_len);
        }

        resp.base.packet_number = htobe32(rx_packet_number + 1);

        if (asft_packet_encrypt(&cresp, &resp, resp_len, ckey)) {
            asft_error("Response encryption failed\n");
            return 1;
        }

        asft_debug("Sending response %u bytes\n", resp_len);

        if (asft_serial_send((unsigned char*) cresp, resp_len) < 0) {
            asft_error("Cannot send response\n");
            return 1;
        }

    }

    return 0;
}

int asft_node_set_gateway(char *label, char *password)
{
    if (strchr(label, '/')) {
        asft_error("Invalid label - contains slash\n");
        goto error;
    }

    free(gw.label);
    free(gw.password);

    gw.label = strdup(label);
    gw.password = strdup(password);

    if (!gw.label || !gw.password)
        goto error;

    return 0;

error:

    free(gw.label);
    free(gw.password);

    gw.label = NULL;
    gw.password = NULL;

    return -1;
}
