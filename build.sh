#!/bin/sh

set -x

CC="gcc"
CFLAGS="-Wall -Werror -std=gnu11"

${CC} -o asft ${CFLAGS} *.c -lcrypto
