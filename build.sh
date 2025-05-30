#!/bin/sh

CC="gcc"
CFLAGS="-Wall -Werror -std=gnu11"

ASFT_SRC="
    asft.c \
    asft_crypto.c \
    asft_file.c \
    asft_gateway.c \
    asft_misc.c \
    asft_node.c \
    asft_serial.c
"

${CC} -o asft ${CFLAGS} *.c -lcrypto
