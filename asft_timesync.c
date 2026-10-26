#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>

#include "asft.h"

// Sample format of chrony SOCK refclock (see refclock_sock.c in chrony sources)
#define SOCK_MAGIC 0x534f434b

struct sock_sample {
    struct timeval tv;
    double offset;
    int pulse;
    int leap;
    int _pad;
    int magic;
};

static char *socket_path = NULL;

int asft_timesync_set_socket(char *path)
{
    struct sockaddr_un addr;

    if (strlen(path) >= sizeof(addr.sun_path)) {
        asft_error("Time sync socket path is too long\n");
        return -1;
    }

    free(socket_path);
    socket_path = strdup(path);

    return socket_path ? 0 : -1;
}

int asft_timesync_enabled()
{
    return !!socket_path;
}

void asft_timesync_sample(uint64_t timestamp_ms, const struct timespec *rx_time)
{
    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    struct sock_sample sample = { .magic = SOCK_MAGIC };

    if (!socket_path)
        return;

    int64_t ref_us = (int64_t) timestamp_ms * 1000;
    int64_t sys_us = (int64_t) rx_time->tv_sec * 1000000 + rx_time->tv_nsec / 1000;

    sample.tv.tv_sec = rx_time->tv_sec;
    sample.tv.tv_usec = rx_time->tv_nsec / 1000;
    sample.offset = (double) (ref_us - sys_us) / 1e6;

    strcpy(addr.sun_path, socket_path);

    int fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        asft_error("Time sync: cannot open socket: %s\n", strerror(errno));
        return;
    }

    if (sendto(fd, &sample, sizeof(sample), 0, (struct sockaddr *) &addr, sizeof(addr)) < 0)
        asft_error("Time sync: cannot send sample to '%s': %s\n", socket_path, strerror(errno));
    else
        asft_debug("Time sync: sample offset %.3f s\n", sample.offset);

    close(fd);
}
