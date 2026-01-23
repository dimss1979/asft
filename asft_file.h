#ifndef _ASFT_FILE_H_
#define _ASFT_FILE_H_

#include "asft_proto.h"

struct asft_msg_tx {
    uint8_t *msg;
    char *path;
    size_t msg_len;
    size_t msg_pos;
    uint8_t seq;
    void *crypto_ctx;
};

struct asft_msg_rx {
    uint8_t *msg;
    size_t msg_len;
    size_t msg_pos;
    uint8_t ack;
    void *crypto_ctx;
};

void asft_msg_tx_init(struct asft_msg_tx *tx, char *dir);
void asft_msg_tx_send(struct asft_msg_tx *tx, uint8_t *pkt_seq, uint8_t *pkt_data);
void asft_msg_tx_ack(struct asft_msg_tx *tx, uint8_t ack);
void asft_msg_tx_cancel(struct asft_msg_tx *tx);

int asft_msg_rx_receive(struct asft_msg_rx *rx, uint8_t pkt_seq, uint8_t *pkt_data, char *dir);
void asft_msg_rx_get_ack(struct asft_msg_rx *rx, uint8_t *ack);
void asft_msg_rx_cancel(struct asft_msg_rx *rx);

#endif /* _ASFT_FILE_H_ */
