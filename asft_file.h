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
};

void asft_file_ctx_init(struct asft_file_ctx *c);
void asft_file_ctx_reset(struct asft_file_ctx *c);
int asft_file_src_open(char *dir, struct asft_file_ctx *c);
int asft_file_dst_open(char *dir, struct asft_file_ctx *c);
int asft_file_name_validate(char *name, unsigned int name_len);

#endif /* _ASFT_FILE_H_ */
