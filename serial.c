#include <stdio.h>
#include <termios.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/file.h>
#include <stdlib.h>
#include <stdbool.h>

#include "serial.h"

#define HDLC_FLAG_BYTE 0x7e
#define HDLC_ESC_BYTE  0x7d
#define HDLC_ESC_MASK  0x20

static int fd = -ENOENT;
static size_t pkt_len_max = 0;
static size_t frame_len_max = 0;
static unsigned char *pkt_rx_buf = NULL;
static unsigned char *frame_tx_buf = NULL;
static int bytes_read = 0;
static size_t bytes_remaining = 0;
static size_t pkt_len = 0;
static unsigned char crc8_local = 0;
static enum {
    HDLC_IDLE,
    HDLC_NORM,
    HDLC_ESC
} hdlc_state = HDLC_IDLE;

static struct {
    char    *br_string;
    speed_t  br_speed;
} baudrate_table[] = {
    {"300",     B300},
    {"1200",    B1200},
    {"115200",  B115200},
};

static speed_t string_to_baudrate(char *baudrate_string)
{
    for (unsigned int i = 0; i < sizeof(baudrate_table) / sizeof(baudrate_table[0]); i++) {
        if (!strcmp(baudrate_table[i].br_string, baudrate_string)) {
            return baudrate_table[i].br_speed;
        }
    }

    return B0;
}

static size_t hdlc_encode(unsigned char *frame_buf, unsigned char *pkt, size_t pkt_len)
{
    unsigned int i;
    unsigned char *frame_pos = frame_buf;
    unsigned char crc8 = 0;

    *frame_pos = HDLC_FLAG_BYTE;
    frame_pos++;

    for (i = 0; i < pkt_len; i++) {
        unsigned char c = pkt[i];
        crc8 += c;
        if (c == HDLC_FLAG_BYTE || c == HDLC_ESC_BYTE) {
            *frame_pos = HDLC_ESC_BYTE;
            frame_pos++;
            c ^= HDLC_ESC_MASK;
        }
        *frame_pos = c;
        frame_pos++;
    }

    if (crc8 == HDLC_FLAG_BYTE || crc8 == HDLC_ESC_BYTE) {
        *frame_pos = HDLC_ESC_BYTE;
        frame_pos++;
        crc8 ^= HDLC_ESC_MASK;
    }
    *frame_pos = crc8;
    frame_pos++;

    *frame_pos = HDLC_FLAG_BYTE;
    frame_pos++;

    return frame_pos - frame_buf;
}

int serial_open(char *devname, char *baudrate_string, size_t _pkt_len_max)
{
    int rv = 0;
    struct termios t;

    serial_close();

    pkt_len_max = _pkt_len_max;
    frame_len_max = 2 * pkt_len_max /* Worst case data */ + 2 /* Flag */ + 2 /* Worst case CRC8 */;

    pkt_rx_buf = malloc(pkt_len_max + 1 /* CRC8 */);
    if (!pkt_rx_buf) {
        fprintf(stderr, "Input packet buffer allocation failed\n");
        rv = -EINVAL;
        goto end;
    }

    frame_tx_buf = malloc(frame_len_max);
    if (!frame_tx_buf) {
        fprintf(stderr, "Output frame buffer allocation failed\n");
        rv = -EINVAL;
        goto end;
    }

    speed_t baudrate = string_to_baudrate(baudrate_string);
    if (baudrate == B0) {
        fprintf(stderr, "Wrong serial port speed: %s\n", baudrate_string);
        rv = -EINVAL;
        goto end;
    }

    fd = open(devname, O_RDWR | O_NOCTTY);
    if (fd < 0) {
        fprintf(stderr, "Cannot open serial port\n");
        rv = fd;
        goto end;
    }

    tcgetattr(fd, &t);
    cfsetispeed(&t, baudrate);
    cfsetospeed(&t, baudrate);
    t.c_cflag = (t.c_cflag & ~CSIZE) | CS8;
    t.c_iflag &= ~IGNBRK;
    t.c_lflag = 0;
    t.c_oflag = 0;
    t.c_cc[VMIN]  = 0;
    t.c_cc[VTIME] = 5; // 0.5 sec TODO 0.1 sec when HDLC is ready
    t.c_iflag &= ~(IXON | IXOFF | IXANY);
    t.c_cflag |= (CLOCAL | CREAD);
    t.c_cflag &= ~(PARENB | PARODD);
    t.c_cflag &= ~CSTOPB;
    t.c_cflag &= ~CRTSCTS;
    if (tcsetattr(fd, TCSANOW, &t) != 0) {
        fprintf(stderr, "Cannot set serial port attributes\n");
        rv = -EINVAL;
        goto end;
    }
    tcflush(fd, TCIOFLUSH);

end:

    if (rv)
        serial_close();

    return rv;
}

void serial_close()
{
    if (fd >= 0) {
        close(fd);
        fd = -ENOENT;
    }
    if (pkt_rx_buf) {
        free(pkt_rx_buf);
        pkt_rx_buf = NULL;
    }
    if (frame_tx_buf) {
        free(frame_tx_buf);
        frame_tx_buf = NULL;
    }
    pkt_len_max = 0;
    frame_len_max = 0;
    bytes_read = 0;
    bytes_remaining = 0;
    pkt_len = 0;
    crc8_local = 0;
    hdlc_state = HDLC_IDLE;
}

int serial_write(unsigned char *pkt, size_t pkt_len)
{
    size_t frame_len;
    unsigned char *pos;
    int bytes_written;
    size_t bytes_remaining;

    if (fd < 0) {
        return -EIO;
    }

    if (pkt_len > pkt_len_max) {
        return -EINVAL;
    }

    frame_len = hdlc_encode(frame_tx_buf, pkt, pkt_len);

    pos = frame_tx_buf;
    bytes_remaining = frame_len;
    while (bytes_remaining) {
        bytes_written = write(fd, pos, bytes_remaining);
        if (bytes_written > 0) {
            pos += bytes_written;
            bytes_remaining -= bytes_written;
        } else if (bytes_written < 0 && bytes_written != -EINTR) {
            fprintf(stderr, "Serial port write error\n");
            serial_close();
            return bytes_written;
        }
    }

    return pkt_len;
}

int serial_read(unsigned char **buf_ptr, size_t *len_ptr)
{
    bool had_read = false;
    int rv = 0;
    static unsigned char read_buf[100];

    *buf_ptr = NULL;
    *len_ptr = 0;

    if (fd < 0) {
        return -EIO;
    }

    if (bytes_remaining) {
        goto process_buf;
    }

again:

    had_read = true;
    bytes_read = read(fd, read_buf, sizeof(read_buf));
    if(bytes_read == -EINTR) {
        goto again;
    } else if(bytes_read < 0) {
        serial_close();
        rv = bytes_read;
        goto end;
    }
    bytes_remaining = bytes_read;

process_buf:

    while (bytes_remaining) {
        unsigned char c = read_buf[bytes_read - bytes_remaining];
        bytes_remaining--;

        if (c == HDLC_FLAG_BYTE && hdlc_state == HDLC_IDLE) {
            hdlc_state = HDLC_NORM;
            pkt_len = 0;
            crc8_local = 0;
        } else if (c == HDLC_FLAG_BYTE && hdlc_state == HDLC_ESC) {
            fprintf(stderr, "HDLC framing error - flag after escape\n");
            hdlc_state = HDLC_IDLE;
            pkt_len = 0;
            crc8_local = 0;
        } else if (c == HDLC_FLAG_BYTE && hdlc_state == HDLC_NORM) {
            if (pkt_len > 1) {
                crc8_local -= pkt_rx_buf[pkt_len - 1];
                if (crc8_local == pkt_rx_buf[pkt_len - 1]) {
                    *buf_ptr = pkt_rx_buf;
                    *len_ptr = pkt_len - 1;
                    pkt_len = 0;
                    crc8_local = 0;
                    goto end;
                } else {
                    fprintf(stderr, "HDLC frame CRC mismatch\n");
                    hdlc_state = HDLC_IDLE;
                    pkt_len = 0;
                    crc8_local = 0;
                }
            } else {
                pkt_len = 0;
                crc8_local = 0;
            }
        } else if (c == HDLC_ESC_BYTE && hdlc_state == HDLC_NORM) {
            hdlc_state = HDLC_ESC;
        } else if (hdlc_state == HDLC_IDLE) {
            /* Ignore input byte */
        } else {
            if (hdlc_state == HDLC_ESC) {
                c ^= HDLC_ESC_MASK;
                hdlc_state = HDLC_NORM;
            }
            if (pkt_len > pkt_len_max) {
                fprintf(stderr, "HDLC framing error - frame too long\n");
                hdlc_state = HDLC_IDLE;
                pkt_len = 0;
                crc8_local = 0;
            } else {
                crc8_local += c;
                pkt_rx_buf[pkt_len] = c;
                pkt_len++;
            }
        }
    }

    if (bytes_read < sizeof(read_buf) && had_read) {
        usleep(20000);
    }

end:

    return rv;
}
