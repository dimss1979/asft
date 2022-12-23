#ifndef _ASFT_SERIAL_H_
#define _ASFT_SERIAL_H_

int asft_serial_init(char *devname, char *baudrate_string, size_t pkt_len_max);
int asft_serial_send(unsigned char *buf, size_t len);
int asft_serial_receive(unsigned char **buf_ptr, size_t *len_ptr);

#endif
