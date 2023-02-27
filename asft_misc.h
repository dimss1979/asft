#ifndef _ASFT_MISC_H_
#define _ASFT_MISC_H_

#include <stdint.h>

void asft_error(const char *format, ...);
void asft_info(const char *format, ...);
void asft_debug(const char *format, ...);
void asft_dump(void *buf, size_t len, char *desc);
void asft_debug_dump(void *buf, size_t len, char *desc);
void asft_set_debug(unsigned int d);
uint64_t asft_now();

#endif /* _ASFT_MISC_H_ */
