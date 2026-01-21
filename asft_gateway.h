#ifndef _ASFT_GATEWAY_H_
#define _ASFT_GATEWAY_H_

#include <stdint.h>

int asft_gateway_loop(void);
int asft_gateway_add_node(char *label, char *password);
void asft_gateway_set_retry_timeout(int new_timeout);
void asft_gateway_set_backoff_time_max(uint32_t new_backoff_time_max);

#endif /* _ASFT_GATEWAY_H_ */
