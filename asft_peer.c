#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif /*_GNU_SOURCE*/

#include <stdlib.h>
#include <string.h>

#include "asft.h"

void asft_peer_clear_key(struct asft_peer *peer)
{
    explicit_bzero(peer->key, sizeof(peer->key));
}

int asft_peer_set_label_key(struct asft_peer *peer, const char *label, const char *key)
{
    char *new_label = NULL;
    size_t key_len = strlen(key);

    if (key_len > ASFT_KEY_B64_LEN) {
        asft_error("Invalid key - too long\n");
        goto error;
    }

    if (strchr(label, '/')) {
        asft_error("Invalid label - contains slash\n");
        goto error;
    }

    new_label = strdup(label);
    if (!new_label)
        goto error;

    free(peer->label);
    peer->label = new_label;

    asft_peer_clear_key(peer);
    memcpy(peer->key, key, key_len + 1);

    return 0;

error:

    return -1;
}
