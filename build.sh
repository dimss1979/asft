#!/bin/sh

set -x

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

${CC} -o asft ${CFLAGS} ${ASFT_SRC} -lcrypto

ASFT_KEYGEN_SRC="
    asft_keygen.c \
    asft_crypto.c \
    asft_misc.c
"

${CC} -o asft_keygen ${CFLAGS} ${ASFT_KEYGEN_SRC} -lcrypto
