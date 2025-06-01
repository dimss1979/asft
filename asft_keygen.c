#include <stdio.h>
#include <string.h>

#include "asft_crypto.h"
#include "asft_misc.h"

int main(int argc, char **argv)
{
    int rv = 1;

    if (argc != 3) {
        asft_error("Usage: asft_keygen <key_file> <passphrase>\n");
        return rv;
    }

    rv = asft_set_key(argv[1], argv[2], strlen(argv[2]));

    if (rv)
        asft_error("Initial key generation failed\n");
    else
        asft_info("Initial key saved to %s\n", argv[1]);

    return rv;
}
