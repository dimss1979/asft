#include <stdio.h>
#include <termios.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/file.h>
#include <stdlib.h>
#include <stdbool.h>

#include "asft_serial.h"

#define HDLC_FLAG_BYTE 0x7e
#define HDLC_ESC_BYTE  0x7d
#define HDLC_ESC_MASK  0x20

static struct _asft_serial_port {
    int fd;
    size_t pkt_len_max;
    size_t frame_len_max;
    unsigned char *pkt_rx_buf;
    unsigned char *frame_tx_buf;
    unsigned char read_buf[100];
    int bytes_read;
    size_t bytes_remaining;
    size_t pkt_len;
    unsigned char crc8_local;
    enum {
        HDLC_IDLE = 0,
        HDLC_NORM,
        HDLC_ESC
    } hdlc_state;
} p = {
    .fd = -1
};

static speed_t string_to_baudrate(char *baudrate_string)
{
    switch(atoi(baudrate_string))
    {
        case 50: return B50;
        case 75: return B75;
        case 110: return B110;
        case 134: return B134;
        case 150: return B150;
        case 200: return B200;
        case 300: return B300;
        case 600: return B600;
        case 1200: return B1200;
        case 1800: return B1800;
        case 2400: return B2400;
        case 4800: return B4800;
        case 9600: return B9600;
        case 19200: return B19200;
        case 38400: return B38400;
        case 57600: return B57600;
        case 115200: return B115200;
        case 230400: return B230400;
        case 500000: return B500000;
        case 576000: return B576000;
        case 921600: return B921600;
        case 1000000: return B1000000;
        case 1152000: return B1152000;
        case 1500000: return B1500000;
        case 2000000: return B2000000;
        case 2500000: return B2500000;
        case 3000000: return B3000000;
        case 3500000: return B3500000;
        case 4000000: return B4000000;
        default: return B0;
    };
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

static void asft_serial_cleanup()
{
    if (p.fd >= 0)
        close(p.fd);
    if (p.pkt_rx_buf)
        free(p.pkt_rx_buf);
    if (p.frame_tx_buf)
        free(p.frame_tx_buf);

    memset(&p, 0, sizeof(p));
    p.fd = -1;
}

int asft_serial_init(char *devname, char *baudrate_string, size_t pkt_len_max)
{
    struct termios t;

    asft_serial_cleanup();

    p.pkt_len_max = pkt_len_max;
    /* Worst case data length + Start/End Flags + Worst case CRC8 */
    p.frame_len_max = 2 * pkt_len_max + 2 + 2;

    p.pkt_rx_buf = malloc(pkt_len_max + 1 /* CRC8 */);
    if (!p.pkt_rx_buf) {
        fprintf(stderr, "Serial input packet buffer allocation failed\n");
        goto error;
    }

    p.frame_tx_buf = malloc(p.frame_len_max);
    if (!p.frame_tx_buf) {
        fprintf(stderr, "Serial output frame buffer allocation failed\n");
        goto error;
    }

    speed_t baudrate = string_to_baudrate(baudrate_string);
    if (baudrate == B0) {
        fprintf(stderr, "Wrong serial port speed: %s\n", baudrate_string);
        goto error;
    }

    p.fd = open(devname, O_RDWR | O_NOCTTY);
    if (p.fd < 0) {
        fprintf(stderr, "Cannot open serial port\n");
        goto error;
    }

    tcgetattr(p.fd, &t);
    cfsetispeed(&t, baudrate);
    cfsetospeed(&t, baudrate);
    t.c_cflag = (t.c_cflag & ~CSIZE) | CS8;
    t.c_iflag &= ~IGNBRK;
    t.c_lflag = 0;
    t.c_oflag = 0;
    t.c_cc[VMIN]  = 0;
    t.c_cc[VTIME] = 1;
    t.c_iflag &= ~(IXON | IXOFF | IXANY);
    t.c_cflag |= (CLOCAL | CREAD);
    t.c_cflag &= ~(PARENB | PARODD);
    t.c_cflag &= ~CSTOPB;
    t.c_cflag &= ~CRTSCTS;
    t.c_iflag &= ~(IGNBRK|BRKINT|PARMRK|ISTRIP|INLCR|IGNCR|ICRNL);
    if (tcsetattr(p.fd, TCSANOW, &t) != 0) {
        fprintf(stderr, "Cannot set serial port attributes\n");
        goto error;
    }
    tcflush(p.fd, TCIOFLUSH);

    return 0;

error:

    asft_serial_cleanup();

    return -1;
}

int asft_serial_send(unsigned char *pkt, size_t pkt_len)
{
    size_t frame_len;
    unsigned char *pos;
    int bytes_written;
    size_t bytes_remaining;

    if (p.fd < 0) {
        return -EIO;
    }

    if (pkt_len > p.pkt_len_max) {
        return -EINVAL;
    }

    frame_len = hdlc_encode(p.frame_tx_buf, pkt, pkt_len);

    pos = p.frame_tx_buf;
    bytes_remaining = frame_len;
    while (bytes_remaining) {
        bytes_written = write(p.fd, pos, bytes_remaining);
        if (bytes_written > 0) {
            pos += bytes_written;
            bytes_remaining -= bytes_written;
        } else if (bytes_written < 0 && bytes_written != -EINTR) {
            fprintf(stderr, "Serial port write error\n");
            asft_serial_cleanup();
            return -EIO;
        }
    }

    return 0;
}

int asft_serial_receive(unsigned char **buf_ptr, size_t *len_ptr)
{
    bool had_read = false;

    *buf_ptr = NULL;
    *len_ptr = 0;

    if (p.fd < 0) {
        return -EIO;
    }

    if (p.bytes_remaining) {
        goto hdlc_decode;
    }

again:

    had_read = true;
    p.bytes_read = read(p.fd, p.read_buf, sizeof(p.read_buf));
    if(p.bytes_read == -EINTR) {
        goto again;
    } else if (p.bytes_read < 0) {
        fprintf(stderr, "Serial port read error\n");
        asft_serial_cleanup();
        return -EIO;
    }
    p.bytes_remaining = p.bytes_read;

hdlc_decode:

    while (p.bytes_remaining) {
        unsigned char c = p.read_buf[p.bytes_read - p.bytes_remaining];
        p.bytes_remaining--;

        if (c == HDLC_FLAG_BYTE && p.hdlc_state == HDLC_IDLE) {
            p.hdlc_state = HDLC_NORM;
            p.pkt_len = 0;
            p.crc8_local = 0;
        } else if (c == HDLC_FLAG_BYTE && p.hdlc_state == HDLC_ESC) {
            fprintf(stderr, "HDLC framing error - flag after escape\n");
            p.hdlc_state = HDLC_IDLE;
            p.pkt_len = 0;
            p.crc8_local = 0;
        } else if (c == HDLC_FLAG_BYTE && p.hdlc_state == HDLC_NORM) {
            if (p.pkt_len > 1) {
                p.crc8_local -= p.pkt_rx_buf[p.pkt_len - 1];
                if (p.crc8_local == p.pkt_rx_buf[p.pkt_len - 1]) {
                    /* Frame received */
                    *buf_ptr = p.pkt_rx_buf;
                    *len_ptr = p.pkt_len - 1;
                    p.pkt_len = 0;
                    p.crc8_local = 0;
                    return 1;
                } else {
                    fprintf(stderr, "HDLC frame CRC mismatch\n");
                    p.hdlc_state = HDLC_IDLE;
                    p.pkt_len = 0;
                    p.crc8_local = 0;
                }
            } else {
                p.pkt_len = 0;
                p.crc8_local = 0;
            }
        } else if (c == HDLC_ESC_BYTE && p.hdlc_state == HDLC_NORM) {
            p.hdlc_state = HDLC_ESC;
        } else if (p.hdlc_state == HDLC_IDLE) {
            /* Ignore input byte */
        } else {
            if (p.hdlc_state == HDLC_ESC) {
                c ^= HDLC_ESC_MASK;
                p.hdlc_state = HDLC_NORM;
            }
            if (p.pkt_len > p.pkt_len_max) {
                fprintf(stderr, "HDLC framing error - frame too long\n");
                p.hdlc_state = HDLC_IDLE;
                p.pkt_len = 0;
                p.crc8_local = 0;
            } else {
                p.crc8_local += c;
                p.pkt_rx_buf[p.pkt_len] = c;
                p.pkt_len++;
            }
        }
    }

    if (p.bytes_read < sizeof(p.read_buf) && had_read) {
        usleep(20000);
    }

    return 0;
}
