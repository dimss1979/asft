#include <stdio.h>
#include <string.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>

#include "asft_crypto.h"
#include "asft_misc.h"

int main(int argc, char **argv)
{
    int rv = 1;
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kctx = NULL;
    OSSL_PARAM params[4], *p = params;
    struct asft_keystore keystore = {0};
    char *keygen_info = "Initial Key";

    if (argc != 3) {
        asft_error("Usage: asft_keygen <key_file> <passphrase>\n");
        return rv;
    }

    kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (!kdf)
        goto error;

    kctx = EVP_KDF_CTX_new(kdf);
    if (!kctx)
        goto error;

    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, SN_blake2b512, strlen(SN_blake2b512));
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, argv[2], strlen(argv[2]));
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, keygen_info, strlen(keygen_info));
    *p = OSSL_PARAM_construct_end();

    if (EVP_KDF_derive(kctx, keystore.key, sizeof(keystore.key), params) != 1)
        goto error;

    if (asft_keystore_save(&keystore, argv[1]))
        goto error;

    rv = 0;

error:

    if (kctx)
        EVP_KDF_CTX_free(kctx);
    if (kdf)
        EVP_KDF_free(kdf);

    if (rv)
        asft_error("Initial key derivation failed\n");
    else
        asft_info("Initial key written to %s\n", argv[1]);

    return rv;
}
