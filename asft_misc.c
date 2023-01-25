#include <stdio.h>
#include <time.h>

#include "asft_misc.h"

void asft_dump(void *buf, size_t len, char *desc)
{
    unsigned char *buf_ = buf;

    printf("%s\n", desc);
    for (int i = 0; i < len; i++)
        printf("%02X ", buf_[i]);
    printf("\n");
}

uint64_t asft_now()
{
    struct timespec now;

    clock_gettime(CLOCK_MONOTONIC, &now);

    return now.tv_sec * 1000ULL + now.tv_nsec / 1000000ULL;
}
