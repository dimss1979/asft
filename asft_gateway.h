#ifndef _ASFT_GATEWAY_H_
#define _ASFT_GATEWAY_H_

void asft_gateway_set_retries(int new_retries);
void asft_gateway_set_retry_timeout(int new_timeout);
void asft_gateway_set_pause_idle(int new_pause_idle);
void asft_gateway_set_pause_error(int new_pause_error);
int asft_gateway_add_node(char *label, char *password);
int asft_gateway_loop();

#endif /* _ASFT_GATEWAY_H_ */
