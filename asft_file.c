#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif /*_GNU_SOURCE*/

#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/types.h>
#include <dirent.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdbool.h>

#include "asft_misc.h"
#include "asft_crypto.h"

#include "asft_file.h"

#define FILE_SIZE_MAX     1000000
#define PATH_LEN (PATH_MAX + 1)

enum data_ack {
    DATA_ACK_NONE = 0,
    DATA_ACK_OK = 1,
    DATA_ACK_RESTART = 2,
};

struct blob_hdr {
    uint8_t hdr_mac[4];
    uint8_t mac[4];
    uint32_t blob_len;
    uint8_t filename_len;
    uint8_t data[];
} __attribute__((packed));

static uint8_t rx_receive_block(struct asft_blob_rx *rx, uint16_t pkt_block_idx, uint8_t *pkt_data, char *dir)
{
    size_t blob_pos = pkt_block_idx * ASFT_BLOCK_LEN;
    size_t bytes_left = rx->blob_len - blob_pos;
    size_t block_len = ASFT_BLOCK_LEN;
    if (bytes_left < ASFT_BLOCK_LEN) {
        block_len = bytes_left;
    }

    memcpy(&rx->blob[blob_pos], pkt_data, block_len);

    if (bytes_left <= ASFT_BLOCK_LEN) {
        struct blob_hdr *hdr = (struct blob_hdr*) rx->blob;

        if (asft_verify_msg(
            rx->crypto_ctx,
            hdr->mac,
            sizeof(hdr->mac),
            hdr->data,
            rx->blob_len - sizeof(*hdr)
        )) {
            asft_error("RX BLOB MAC mismatch\n");
            return DATA_ACK_RESTART;
        }

        char filename[256] = {0};
        memcpy(filename, hdr->data, hdr->filename_len);
        char path_tmp[PATH_LEN] = {0};
        char path[PATH_LEN] = {0};

        sprintf(path_tmp, "%s/.tmp", dir);
        sprintf(path, "%s/%s", dir, filename);
        asft_info("Received file '%s'\n", path);

        int fd = open(
            path_tmp,
            O_WRONLY | O_CREAT | O_TRUNC,
            S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH
        );
        if (fd < 0) {
            asft_error("Cannot open destination file %s\n", path_tmp);
            return DATA_ACK_NONE;
        }

        uint8_t *buf = &hdr->data[hdr->filename_len];
        size_t left = rx->blob_len - hdr->filename_len - sizeof(struct blob_hdr);

        while (left) {
            int rv = write(fd, buf, left);
            if (rv < 0) {
                if (errno == EINTR)
                    continue;
                asft_error("Write failed\n");
                return DATA_ACK_NONE;
            }

            left -= rv;
            buf += rv;
        }
        close(fd);

        if (rename(path_tmp, path)) {
            asft_error("Rename failed\n");
            return DATA_ACK_NONE;
        }

        sync();
    }

    rx->last_block_idx = pkt_block_idx;
    memcpy(rx->last_block, pkt_data, ASFT_BLOCK_LEN);

    return DATA_ACK_OK;
}

void asft_blob_tx_init(struct asft_blob_tx *tx, char *dir)
{
    if (tx->blob)
        return;

    char path[PATH_LEN], filename[PATH_LEN];
    DIR *d = opendir(dir);
    if (!d) {
        asft_error("Cannot list directory '%s'\n", dir);
        goto error;
    }

    struct dirent *e;
    size_t filename_len = 0, file_len = 0;
    struct timespec ctime_min = {0};
    bool ctime_min_valid = false;

    while ((e = readdir(d))) {
        char path_tmp[PATH_LEN];
        struct stat64 s, ls;

        if (e->d_type != DT_LNK && e->d_type != DT_REG)
            continue;
        if (e->d_name[0] == '.')
            continue;
        if (snprintf(path_tmp, sizeof(path_tmp) - 1, "%s/%s", dir, e->d_name) < 0)
            continue;
        if (stat64(path_tmp, &s))
            continue;
        file_len = s.st_size;
        if (file_len > FILE_SIZE_MAX)
            continue;
        filename_len = strlen(e->d_name);
        if (lstat64(path_tmp, &ls))
            continue;
        if (
            ctime_min_valid &&
            (
                (ls.st_ctim.tv_sec > ctime_min.tv_sec) ||
                (
                    (ls.st_ctim.tv_sec == ctime_min.tv_sec) &&
                    (ls.st_ctim.tv_nsec > ctime_min.tv_nsec)
                )
            )
        ) {
            continue;
        }

        ctime_min = ls.st_ctim;
        ctime_min_valid = true;
        memcpy(path, path_tmp, PATH_LEN);
        memcpy(filename, e->d_name, filename_len);
    }

    closedir(d);
    d = NULL;

    if (!ctime_min_valid)
        return;

    asft_info("Sending file '%s' %li bytes\n", path, file_len);

    size_t blob_len = sizeof(struct blob_hdr) + filename_len + file_len;
    tx->blob = malloc(blob_len);
    tx->path = strdup(path);
    if (!tx->blob || !tx->path) {
        asft_error("TX BLOB memory allocation error\n");
        goto error;
    }

    struct blob_hdr *hdr = (struct blob_hdr*) tx->blob;
    hdr->blob_len = htobe32(blob_len);
    hdr->filename_len = filename_len;
    tx->blob_len = blob_len;
    tx->blob_pos = 0;
    memcpy(hdr->data, filename, filename_len);

    int fd = open(path, O_RDONLY, 0);
    if (fd < 0) {
        asft_error("Cannot open TX BLOB input file\n");
        goto error;
    }

    size_t bytes_left = file_len;
    uint8_t *blob_pos = &hdr->data[filename_len];
    while (bytes_left) {
        size_t bytes_read = read(fd, blob_pos, bytes_left);
        if (bytes_read <= 0) {
            if (errno == EINTR)
                continue;
            asft_error("TX BLOB read failed\n");
            goto error;
        }
        blob_pos += bytes_read;
        bytes_left -= bytes_read;
    }
    close(fd);
    fd = -1;

    if (asft_sign_msg(
        tx->crypto_ctx,
        hdr->mac,
        sizeof(hdr->mac),
        hdr->data,
        tx->blob_len - sizeof(*hdr)
    )) {
        asft_error("TX BLOB MAC failed\n");
        goto error;
    }

    if (asft_sign_msg_hdr(
        tx->crypto_ctx,
        hdr->hdr_mac,
        sizeof(hdr->hdr_mac),
        ((void*) hdr) + sizeof(hdr->hdr_mac),
        sizeof(*hdr) - sizeof(hdr->hdr_mac)
    )) {
        asft_error("TX BLOB header MAC failed\n");
        goto error;
    }


    return;

error:

    if (fd >= 0)
        close(fd);
    if (d)
        closedir(d);

    free(tx->blob);
    tx->blob = NULL;
    free(tx->path);
    tx->path = NULL;
}

void asft_blob_tx_send(struct asft_blob_tx *tx, uint16_t *pkt_block_idx, uint8_t *pkt_data)
{
    if (!tx->blob) {
        asft_error("TX BLOB not initialized but sending\n");
        return;
    }

    *pkt_block_idx = tx->blob_pos / ASFT_BLOCK_LEN;
    memset(pkt_data, 0, ASFT_BLOCK_LEN);

    size_t bytes_left = tx->blob_len - tx->blob_pos;
    size_t block_len = ASFT_BLOCK_LEN;
    if (bytes_left < ASFT_BLOCK_LEN)
        block_len = bytes_left;

    memcpy(pkt_data, &tx->blob[tx->blob_pos], block_len);
}

void asft_blob_tx_ack(struct asft_blob_tx *tx, uint8_t ack)
{
    if (!tx->blob) {
        return;
    }

    switch (ack) {
        case DATA_ACK_NONE:
            break;

        case DATA_ACK_OK:
            size_t bytes_left = tx->blob_len - tx->blob_pos;
            if (bytes_left > ASFT_BLOCK_LEN) {
                tx->blob_pos += ASFT_BLOCK_LEN;
            } else {
                asft_info("Sent file '%s'\n", tx->path);
                unlink(tx->path);
                sync();
                free(tx->path);
                free(tx->blob);
                tx->path = NULL;
                tx->blob = NULL;
            }
            break;

        case DATA_ACK_RESTART:
            tx->blob_pos = 0;
            break;

        default:
            asft_error("TX BLOB received invalid ack\n");
            break;
    }
}

void asft_blob_rx_receive(struct asft_blob_rx *rx, uint16_t pkt_block_idx, uint8_t *pkt_data, char *dir)
{
    if (pkt_block_idx == rx->last_block_idx && !memcmp(pkt_data, rx->last_block, ASFT_BLOCK_LEN)) {
        rx->ack = DATA_ACK_OK;
    } else if (pkt_block_idx == 0) {
        struct blob_hdr *hdr = (struct blob_hdr*) pkt_data;

        if (asft_verify_msg_hdr(
            rx->crypto_ctx,
            hdr->hdr_mac,
            sizeof(hdr->hdr_mac),
            ((void*) hdr) + sizeof(hdr->hdr_mac),
            sizeof(*hdr) - sizeof(hdr->hdr_mac)
        )) {
            asft_error("RX BLOB header MAC mismatch\n");
            rx->ack = DATA_ACK_RESTART;
            return;
        }

        size_t blob_len = be32toh(hdr->blob_len);
        size_t blob_len_max = sizeof(struct blob_hdr) + hdr->filename_len + FILE_SIZE_MAX;
        if (blob_len > blob_len_max) {
            asft_error("RX BLOB is too big\n");
            rx->ack = DATA_ACK_NONE;
            return;
        }

        rx->blob_len = 0;
        rx->last_block_idx = 0;
        memset(rx->last_block, 0 , ASFT_BLOCK_LEN);
        free(rx->blob);
        rx->blob = malloc(blob_len);
        if (!rx->blob) {
            asft_error("RX BLOB memory allocation error\n");
            rx->ack = DATA_ACK_NONE;
            return;
        }
        rx->blob_len = blob_len;

        rx->ack = rx_receive_block(rx, pkt_block_idx, pkt_data, dir);
    } else if (rx->blob && (pkt_block_idx == rx->last_block_idx + 1)) {
        rx->ack = rx_receive_block(rx, pkt_block_idx, pkt_data, dir);
    } else {
        asft_error("RX BLOB out-of-order block\n");
        rx->ack = DATA_ACK_RESTART;
    }
}

void asft_blob_rx_get_ack(struct asft_blob_rx *rx, uint8_t *ack)
{
    *ack = rx->ack;
    rx->ack = DATA_ACK_NONE;
}
