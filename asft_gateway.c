#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>

#include "asft_proto.h"
#include "asft_crypto.h"
#include "asft_serial.h"

#include "asft_gateway.h"

int asft_gateway_loop()
{
    unsigned char key[ASFT_KEY_LEN];
    asft_packet pkt, *cpkt = NULL;
    uint32_t session_token = 0;
    uint32_t dialog_token = -1;

    memset(key, 0xaa, sizeof(key));
    memset(&pkt, 0, sizeof(pkt));

    while(1)
    {
        int rv;
        size_t pkt_len = sizeof(pkt);
        unsigned char *buf;

        pkt.cmd.base.dst_addr = 1;
        pkt.cmd.cmd.command = 0x33;
        pkt.cmd.cmd.session_token = htonl(session_token++);
        pkt.cmd.cmd.dialog_token = htonl(dialog_token--);
        printf("Sending packet:\n");
        buf = (unsigned char*) &pkt;
        for (int i = 0; i < pkt_len; i++)
            printf("%02X ", buf[i]);
        printf("\n");

        rv = asft_packet_encrypt(&cpkt, &pkt, pkt_len, key);
        if (rv || !cpkt) {
            fprintf(stderr, "Cannot encrypt packet\n");
            return 1;
        }
        printf("Sending encrypted packet:\n");
        buf = (unsigned char*) cpkt;
        for (int i = 0; i < pkt_len; i++)
            printf("%02X ", buf[i]);
        printf("\n\n");

        rv = asft_serial_send((unsigned char*) cpkt, pkt_len);
        if (rv < 0) {
            fprintf(stderr, "Cannot send to serial port\n");
            return 1;
        }

        sleep(3);
    }

    return 0;
}
