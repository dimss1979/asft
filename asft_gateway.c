#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/random.h>

#include "asft_proto.h"
#include "asft_crypto.h"
#include "asft_serial.h"
#include "asft_misc.h"

#include "asft_gateway.h"

int asft_gateway_loop()
{
    unsigned char key[ASFT_KEY_LEN];
    asft_packet *cpkt = NULL;

    memset(key, 0xaa, sizeof(key));

    while(1)
    {
        int rv;
        struct asft_cmd_ecdh pkt;
        size_t pkt_len = sizeof(pkt);

        pkt_len = sizeof(pkt);
        pkt.base.dst_addr = 1;
        pkt.cmd.command = ASFT_REQ_ECDH_KEY;
        getrandom(&pkt.cmd.packet_number, sizeof(pkt.cmd.packet_number), 0);
        memset(&pkt.public_key, 'x', sizeof(pkt.public_key));
        asft_dump(&pkt, sizeof(pkt), "Prepared packet");

        rv = asft_packet_encrypt(&cpkt, &pkt, pkt_len, key);
        if (rv || !cpkt) {
            fprintf(stderr, "Cannot encrypt packet\n");
            return 1;
        }
        asft_dump(cpkt, pkt_len, "Encrypted packet");

        rv = asft_serial_send((unsigned char*) cpkt, pkt_len);
        if (rv < 0) {
            fprintf(stderr, "Cannot send packet\n");
            return 1;
        }

        sleep(3);
    }

    return 0;
}
