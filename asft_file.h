#ifndef _ASFT_FILE_H_
#define _ASFT_FILE_H_

struct asft_file_ctx {
    int fd;
    char *name;
    unsigned int name_len;
    char *path;
    char *path_tmp;
    uint32_t size;
    uint32_t left;
    uint32_t block;
    uint32_t blocks;
    unsigned char data[ASFT_BLOCK_LEN];
    unsigned int data_len;
};

void asft_file_ctx_init(struct asft_file_ctx *c);
void asft_file_ctx_reset(struct asft_file_ctx *c);
int asft_file_src_open(struct asft_file_ctx *c, char *dir);
int asft_file_dst_open(struct asft_file_ctx *c, char *dir, char *name, unsigned int name_len, uint32_t size);
int asft_file_src_read(struct asft_file_ctx *c, void *data, unsigned int data_len);
int asft_file_dst_write(struct asft_file_ctx *c, void *data, unsigned int data_len);
int asft_file_src_complete(struct asft_file_ctx *c);
int asft_file_dst_complete(struct asft_file_ctx *c);

#endif /* _ASFT_FILE_H_ */
