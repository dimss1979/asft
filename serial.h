#ifndef _ASFT_SERIAL_H_
#define _ASFT_SERIAL_H_

int serial_open(char *devname, char *baudrate_string, size_t _pkt_len_max);
void serial_close();
int serial_write(unsigned char *buf, size_t len);
int serial_read(unsigned char **buf_ptr, size_t *len_ptr);

#endif
