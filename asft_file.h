#ifndef _ASFT_FILE_H_
#define _ASFT_FILE_H_

#include "asft_proto.h"

struct asft_blob_tx {
    uint8_t *blob;
    char *path;
    size_t blob_len;
    size_t blob_pos;
    void *crypto_ctx;
};

struct asft_blob_rx {
    uint8_t *blob;
    size_t blob_len;
    uint16_t last_block_idx;
    uint8_t last_block[ASFT_BLOCK_LEN];
    uint8_t ack;
    void *crypto_ctx;
};

void asft_blob_tx_init(struct asft_blob_tx *tx, char *dir);
void asft_blob_tx_send(struct asft_blob_tx *tx, uint16_t *pkt_block_idx, uint8_t *pkt_data);
void asft_blob_tx_ack(struct asft_blob_tx *tx, uint8_t ack);

void asft_blob_rx_receive(struct asft_blob_rx *rx, uint16_t pkt_block_idx, uint8_t *pkt_data, char *dir);
void asft_blob_rx_get_ack(struct asft_blob_rx *rx, uint8_t *ack);

#endif /* _ASFT_FILE_H_ */
