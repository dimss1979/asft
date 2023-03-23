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

#include "asft_misc.h"
#include "asft_proto.h"

#include "asft_file.h"

void asft_file_ctx_init(struct asft_file_ctx *c)
{
    memset(c, 0, sizeof(*c));
    c->fd = -1;
}

void asft_file_ctx_reset(struct asft_file_ctx *c)
{
    if (c->fd >= 0)
        close(c->fd);

    free(c->name);
    free(c->path);
    free(c->path_tmp);

    asft_file_ctx_init(c);
}

int asft_file_src_open(char *dir, struct asft_file_ctx *c)
{
    DIR *d;
    struct dirent *e;
    char path[1024];
    struct stat64 s;
    unsigned int name_len;

    asft_file_ctx_reset(c);
    d = opendir(dir);
    if (!d) {
        asft_error("Cannot list directory '%s'\n", dir);
        goto error;
    }

    while ((e = readdir(d))) {
        if (e->d_type != DT_LNK && e->d_type != DT_REG)
            continue;
        if (e->d_name[0] == '.')
            continue;
        if (snprintf(path, sizeof(path), "%s/%s", dir, e->d_name) < 0)
            continue;
        path[sizeof(path) - 1] = 0;
        if (stat64(path, &s))
            continue;
        if (s.st_size > UINT32_MAX)
            continue;
        name_len = strlen(e->d_name);
        if (name_len > ASFT_FILE_NAME_LEN)
            continue;
        c->fd = open(path, O_RDONLY, 0);
        if (c->fd < 0)
            continue;

        c->size = s.st_size;
        c->left = c->size;
        c->name = strdup(e->d_name);
        c->path = strdup(path);
        c->name_len = name_len;
        if (!c->name || !c->path)
            goto error;

        break;
    }

    closedir(d);

    return 0;

error:

    asft_file_ctx_reset(c);

    return 1;
}

int asft_file_dst_open(char *dir, struct asft_file_ctx *c)
{
    free(c->path);
    free(c->path_tmp);
    if (asprintf(&c->path, "%s/%s", dir, c->name) < 0)
        goto error;
    if (asprintf(&c->path_tmp, "%s/.tmp_file", dir) < 0)
        goto error;

    c->fd = open(
        c->path_tmp,
        O_WRONLY | O_CREAT | O_TRUNC,
        S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH
    );
    if (c->fd < 0) {
        asft_error("Cannot open destination file %s\n", c->path_tmp);
        goto error;
    }

    return 0;

error:

    asft_file_ctx_reset(c);

    return -1;
}

int asft_file_src_read(struct asft_file_ctx *c, void *data, unsigned int data_len)
{
    int rv = 0;
    unsigned int left = data_len;

    while (left) {
        rv = read(c->fd, data, left);
        if (rv < 0) {
            if (errno == EINTR)
                continue;
            asft_error("Read failed\n");
            return rv;
        } else if (rv == 0) {
            asft_error("Read failed - EOF\n");
            return -EIO;
        }

        left -= rv;
        data += rv;
    };

    return 0;
}

int asft_file_dst_write(struct asft_file_ctx *c, void *data, unsigned int data_len)
{
    int rv = 0;
    unsigned int left = data_len;

    while (left) {
        rv = write(c->fd, data, left);
        if (rv < 0) {
            if (errno == EINTR)
                continue;
            asft_error("Write failed\n");
            return rv;
        }

        left -= rv;
        data += rv;
    };

    return 0;
}

int asft_file_src_complete(struct asft_file_ctx *c)
{
    int rv = 0;

    if (unlink(c->path)) {
        asft_error("Unlink failed\n");
        rv = -1;
    }
    asft_file_ctx_reset(c);

    return rv;
}

int asft_file_dst_complete(struct asft_file_ctx *c)
{
    int rv = 0;

    if (rename(c->path_tmp, c->path)) {
        asft_error("Rename failed\n");
        rv = -1;
    }
    asft_file_ctx_reset(c);

    return rv;
}

int asft_file_name_validate(char *name, unsigned int name_len)
{
    if (strlen(name) != name_len) {
        asft_debug("Invalid filename - null character\n");
        return 1;
    }

    if (name[0] == '.') {
        asft_debug("Invalid filename - leading dot\n");
        return 1;
    }

    if (strchr(name, '/')) {
        asft_debug("Invalid filename - contains slash\n");
        return 1;
    }

    return 0;
}
