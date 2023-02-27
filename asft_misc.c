#include <stdio.h>
#include <time.h>
#include <stdarg.h>

#include "asft_misc.h"

static unsigned int debug = 0;

void asft_error(const char *format, ...)
{
    va_list argptr;

    va_start(argptr, format);
    vfprintf(stderr, format, argptr);
    va_end(argptr);
}

void asft_info(const char *format, ...)
{
    va_list argptr;

    va_start(argptr, format);
    vfprintf(stdout, format, argptr);
    va_end(argptr);
}

void asft_debug(const char *format, ...)
{
    va_list argptr;

    if (!debug)
        return;

    va_start(argptr, format);
    vfprintf(stdout, format, argptr);
    va_end(argptr);
}

void asft_dump(void *buf, size_t len, char *desc)
{
    unsigned char *buf_ = buf;

    printf("%s\n", desc);
    for (int i = 0; i < len; i++)
        printf("%02X ", buf_[i]);
    printf("\n");
}

void asft_debug_dump(void *buf, size_t len, char *desc)
{
    if (!debug)
        return;

    asft_dump(buf, len, desc);
}

void asft_set_debug(unsigned int d)
{
    debug = d;
}

uint64_t asft_now()
{
    struct timespec now;

    clock_gettime(CLOCK_MONOTONIC, &now);

    return now.tv_sec * 1000ULL + now.tv_nsec / 1000000ULL;
}
