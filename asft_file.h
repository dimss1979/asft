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
    unsigned char data[ASFT_BLOCK_LEN];
    unsigned int data_len;
};

void asft_file_ctx_init(struct asft_file_ctx *c);
void asft_file_ctx_reset(struct asft_file_ctx *c);
int asft_file_src_open(char *dir, struct asft_file_ctx *c);
int asft_file_dst_open(char *dir, struct asft_file_ctx *c);
int asft_file_src_read(struct asft_file_ctx *c, void *data, unsigned int data_len);
int asft_file_dst_write(struct asft_file_ctx *c, void *data, unsigned int data_len);
int asft_file_src_complete(struct asft_file_ctx *c);
int asft_file_dst_complete(struct asft_file_ctx *c);
int asft_file_name_validate(char *name, unsigned int name_len);

#endif /* _ASFT_FILE_H_ */
