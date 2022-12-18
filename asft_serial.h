#ifndef _ASFT_SERIAL_H_
#define _ASFT_SERIAL_H_

typedef struct _asft_serial *asft_serial;

asft_serial asft_serial_open(char *devname, char *baudrate_string, size_t pkt_len_max);
void asft_serial_close(asft_serial p);
int asft_serial_send(asft_serial p, unsigned char *buf, size_t len);
int asft_serial_receive(asft_serial p, unsigned char **buf_ptr, size_t *len_ptr);

#endif
