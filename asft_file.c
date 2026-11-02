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

#include "asft.h"

#define FILE_SIZE_MAX     1000000
#define PATH_LEN (PATH_MAX + 1)

struct msg_hdr {
    uint8_t hdr_mac[4];
    uint8_t mac[4];
    uint32_t msg_len;
    uint8_t filename_len;
    uint8_t data[];
} __attribute__((packed));

static bool filename_is_safe(const char *name, size_t len)
{
    if (len == 0 || len > 255)
        return false;

    /* Reject "." and ".." to prevent directory traversal. */
    if ((len == 1 && name[0] == '.') ||
        (len == 2 && name[0] == '.' && name[1] == '.'))
        return false;

    for (size_t i = 0; i < len; i++) {
        unsigned char c = name[i];

        /* No path separators, control characters or other metadata. */
        if (c == '/' || c == '\\')
            return false;
        if (c < 0x20 || c == 0x7f)
            return false;
    }

    return true;
}


void asft_msg_tx_init(struct asft_msg_tx *tx, char *dir)
{
    int fd = -1;

    if (tx->msg)
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

    size_t msg_len = sizeof(struct msg_hdr) + filename_len + file_len;
    tx->msg = malloc(msg_len);
    tx->path = strdup(path);
    if (!tx->msg || !tx->path) {
        asft_error("TX MSG memory allocation error\n");
        goto error;
    }

    struct msg_hdr *hdr = (struct msg_hdr*) tx->msg;
    hdr->msg_len = htobe32(msg_len);
    hdr->filename_len = filename_len;
    tx->msg_len = msg_len;
    tx->msg_pos = 0;
    memcpy(hdr->data, filename, filename_len);

    fd = open(path, O_RDONLY, 0);
    if (fd < 0) {
        asft_error("Cannot open TX MSG input file\n");
        goto error;
    }

    size_t bytes_left = file_len;
    uint8_t *msg_pos = &hdr->data[filename_len];
    while (bytes_left) {
        size_t bytes_read = read(fd, msg_pos, bytes_left);
        if (bytes_read <= 0) {
            if (errno == EINTR)
                continue;
            asft_error("TX MSG read failed\n");
            goto error;
        }
        msg_pos += bytes_read;
        bytes_left -= bytes_read;
    }
    close(fd);
    fd = -1;

    if (asft_sign_msg(
        tx->crypto_ctx,
        hdr->mac,
        sizeof(hdr->mac),
        hdr->data,
        tx->msg_len - sizeof(*hdr)
    )) {
        asft_error("TX MSG MAC failed\n");
        goto error;
    }

    if (asft_sign_msg_hdr(
        tx->crypto_ctx,
        hdr->hdr_mac,
        sizeof(hdr->hdr_mac),
        ((void*) hdr) + sizeof(hdr->hdr_mac),
        sizeof(*hdr) - sizeof(hdr->hdr_mac)
    )) {
        asft_error("TX MSG header MAC failed\n");
        goto error;
    }


    return;

error:

    if (fd >= 0)
        close(fd);
    if (d)
        closedir(d);

    free(tx->msg);
    tx->msg = NULL;
    free(tx->path);
    tx->path = NULL;
}

void asft_msg_tx_send(struct asft_msg_tx *tx, uint8_t *pkt_seq, uint8_t *pkt_data)
{
    if (!tx->msg) {
        asft_error("TX MSG not initialized but sending\n");
        return;
    }

    memset(pkt_data, 0, ASFT_BLOCK_LEN);

    size_t bytes_left = tx->msg_len - tx->msg_pos;
    size_t block_len = ASFT_BLOCK_LEN;
    if (bytes_left < ASFT_BLOCK_LEN)
        block_len = bytes_left;

    memcpy(pkt_data, &tx->msg[tx->msg_pos], block_len);
    *pkt_seq = tx->seq;
}

void asft_msg_tx_ack(struct asft_msg_tx *tx, uint8_t ack)
{
    if (!tx->msg) {
        return;
    }

    if (ack != tx->seq) {
        return;
    }

    size_t bytes_left = tx->msg_len - tx->msg_pos;
    if (bytes_left > ASFT_BLOCK_LEN) {
        tx->msg_pos += ASFT_BLOCK_LEN;
    } else {
        asft_info("Sent file '%s'\n", tx->path);
        unlink(tx->path);
        sync();
        free(tx->path);
        free(tx->msg);
        tx->path = NULL;
        tx->msg = NULL;
    }

    tx->seq ^= 1;
}

int asft_msg_rx_receive(struct asft_msg_rx *rx, uint8_t pkt_seq, uint8_t *pkt_data, char *dir)
{
    int fd = -1;

    if (pkt_seq == rx->ack) {
        return 0;
    }

    rx->ack = pkt_seq;

    if (!rx->msg) {
        struct msg_hdr *hdr = (struct msg_hdr*) pkt_data;

        if (asft_verify_msg_hdr(
            rx->crypto_ctx,
            hdr->hdr_mac,
            sizeof(hdr->hdr_mac),
            ((void*) hdr) + sizeof(hdr->hdr_mac),
            sizeof(*hdr) - sizeof(hdr->hdr_mac)
        )) {
            asft_error("RX MSG header MAC mismatch\n");
            goto error;
        }

        size_t msg_len = be32toh(hdr->msg_len);
        size_t msg_len_min = sizeof(struct msg_hdr) + hdr->filename_len;
        size_t msg_len_max = sizeof(struct msg_hdr) + hdr->filename_len + FILE_SIZE_MAX;
        if (msg_len < msg_len_min) {
            asft_error("RX MSG is too small\n");
            goto error;
        }
        if (msg_len > msg_len_max) {
            asft_error("RX MSG is too big\n");
            goto error;
        }

        rx->msg = malloc(msg_len);
        if (!rx->msg) {
            asft_error("RX MSG memory allocation error\n");
            goto error;
        }
        rx->msg_len = msg_len;
        rx->msg_pos = 0;

        asft_debug("Receiving file\n");
    }

    size_t bytes_left = rx->msg_len - rx->msg_pos;
    size_t block_len = ASFT_BLOCK_LEN;
    if (bytes_left < ASFT_BLOCK_LEN) {
        block_len = bytes_left;
    }

    memcpy(&rx->msg[rx->msg_pos], pkt_data, block_len);

    if (bytes_left > ASFT_BLOCK_LEN) {
        rx->msg_pos += ASFT_BLOCK_LEN;
    } else {
        struct msg_hdr *hdr = (struct msg_hdr*) rx->msg;

        if (asft_verify_msg(
            rx->crypto_ctx,
            hdr->mac,
            sizeof(hdr->mac),
            hdr->data,
            rx->msg_len - sizeof(*hdr)
        )) {
            asft_error("RX MSG MAC mismatch\n");
            goto error;
        }

        char filename[256] = {0};
        memcpy(filename, hdr->data, hdr->filename_len);

        if (!filename_is_safe(filename, hdr->filename_len)) {
            asft_error("RX MSG has an invalid filename\n");
            goto error;
        }

        char path_tmp[PATH_LEN] = {0};
        char path[PATH_LEN] = {0};

        int path_len = snprintf(path_tmp, sizeof(path_tmp), "%s/.asft-XXXXXX", dir);
        if (path_len < 0 || (size_t) path_len >= sizeof(path_tmp)) {
            asft_error("Destination path is too long\n");
            goto error;
        }
        path_len = snprintf(path, sizeof(path), "%s/%s", dir, filename);
        if (path_len < 0 || (size_t) path_len >= sizeof(path)) {
            asft_error("Destination path is too long\n");
            goto error;
        }
        asft_info("Received file '%s'\n", path);

        /* mkstemp() creates the file with O_EXCL and mode 0600 in the
         * destination directory, avoiding symlink attacks and keeping
         * the data private until it is renamed into place. */
        fd = mkstemp(path_tmp);
        if (fd < 0) {
            asft_error("Cannot create destination file %s\n", path_tmp);
            goto error;
        }

        uint8_t *buf = &hdr->data[hdr->filename_len];
        size_t left = rx->msg_len - hdr->filename_len - sizeof(struct msg_hdr);

        while (left) {
            ssize_t rv = write(fd, buf, left);
            if (rv < 0) {
                if (errno == EINTR)
                    continue;
                asft_error("Write failed\n");
                unlink(path_tmp);
                goto error;
            }
            if (rv == 0) {
                asft_error("Write failed\n");
                unlink(path_tmp);
                goto error;
            }

            left -= rv;
            buf += rv;
        }
        if (close(fd) < 0) {
            asft_error("Close failed\n");
            fd = -1;
            unlink(path_tmp);
            goto error;
        }
        fd = -1;

        if (rename(path_tmp, path)) {
            asft_error("Rename failed\n");
            unlink(path_tmp);
            goto error;
        }

        sync();

        free(rx->msg);
        rx->msg = NULL;
    }

    return 0;

error:

    if (fd >= 0) {
        close(fd);
    }

    return 1;
}

void asft_msg_rx_get_ack(struct asft_msg_rx *rx, uint8_t *ack)
{
    *ack = rx->ack;
}

void asft_msg_tx_cancel(struct asft_msg_tx *tx)
{
    if (tx->msg) {
        free(tx->msg);
        tx->msg = NULL;
    }
    if (tx->path) {
        free(tx->path);
        tx->path = NULL;
    }
    tx->msg_len = 0;
    tx->msg_pos = 0;
    tx->seq = 1;
}

void asft_msg_rx_cancel(struct asft_msg_rx *rx)
{
    if (rx->msg) {
        free(rx->msg);
        rx->msg = NULL;
    }
    rx->msg_len = 0;
    rx->msg_pos = 0;
    rx->ack = 0;
}
