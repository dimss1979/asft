#include <stdio.h>

#include "asft_misc.h"

void asft_dump(void *buf, size_t len, char *desc)
{
    unsigned char *buf_ = buf;

    printf("%s\n", desc);
    for (int i = 0; i < len; i++)
        printf("%02X ", buf_[i]);
    printf("\n");
}
