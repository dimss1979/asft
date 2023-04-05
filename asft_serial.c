#include <stdio.h>
#include <termios.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/file.h>
#include <stdlib.h>
#include <stdbool.h>

#include "asft_misc.h"

#include "asft_serial.h"

static struct {
    int fd;
    unsigned char read_buf[100];
    int bytes_read;
    size_t bytes_remaining;

    unsigned char *pkt_rx_buf;
    size_t pkt_len_max;

    unsigned char *frame_tx_buf;
    size_t frame_tx_len_max;

    unsigned char *frame_rx_buf;
    size_t frame_rx_len;
    size_t frame_rx_len_max;
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
    }
}

static size_t cobs_encode(const uint8_t * restrict input, size_t length, uint8_t * restrict output)
{
    size_t read_index = 0;
    size_t write_index = 1;
    size_t code_index = 0;
    uint8_t code = 1;

    while(read_index < length) {
        if(input[read_index] == 0) {
            output[code_index] = code;
            code = 1;
            code_index = write_index;
            write_index++;
            read_index++;
        } else {
            output[write_index] = input[read_index];
            write_index++;
            read_index++;
            code++;
            if(code == 0xff) {
                output[code_index] = code;
                code = 1;
                code_index = write_index;
                write_index++;
            }
        }
    }

    output[code_index] = code;

    return write_index;
}

static size_t cobs_decode(const uint8_t * restrict input, size_t length, uint8_t * restrict output)
{
    size_t read_index = 0;
    size_t write_index = 0;
    uint8_t code;
    uint8_t i;

    while (read_index < length) {
        code = input[read_index];

        if(read_index + code > length && code != 1)
            return 0;

        read_index++;

        for (i = 1; i < code; i++) {
            output[write_index] = input[read_index];
            write_index++;
            read_index++;
        }

        if (code != 0xff && read_index != length) {
            output[write_index] = 0x00;
            write_index++;
        }
    }

    return write_index;
}

static void asft_serial_cleanup()
{
    if (p.fd >= 0)
        close(p.fd);
    if (p.pkt_rx_buf)
        free(p.pkt_rx_buf);
    if (p.frame_tx_buf)
        free(p.frame_tx_buf);
    if (p.frame_rx_buf)
        free(p.frame_rx_buf);

    memset(&p, 0, sizeof(p));
    p.fd = -1;
}

int asft_serial_init(char *devname, char *baudrate_string, size_t pkt_len_max)
{
    struct termios t;
    speed_t baudrate;

    asft_serial_cleanup();

    p.pkt_len_max = pkt_len_max;
    p.frame_rx_len_max = pkt_len_max + ((pkt_len_max / 254) + 1) /* overhead */;
    p.frame_tx_len_max = p.frame_rx_len_max + 2 /* start and stop delimiter */;

    p.pkt_rx_buf = malloc(pkt_len_max + 1 /* checksum */);
    if (!p.pkt_rx_buf) {
        asft_error("Serial input packet buffer allocation failed\n");
        goto error;
    }

    p.frame_tx_buf = malloc(p.frame_tx_len_max);
    if (!p.frame_tx_buf) {
        asft_error("Serial output frame buffer allocation failed\n");
        goto error;
    }

    p.frame_rx_buf = malloc(p.frame_rx_len_max);
    if (!p.frame_rx_buf) {
        asft_error("Serial input frame buffer allocation failed\n");
        goto error;
    }

    baudrate = string_to_baudrate(baudrate_string);
    if (baudrate == B0) {
        asft_error("Wrong serial port speed: %s\n", baudrate_string);
        goto error;
    }

    p.fd = open(devname, O_RDWR | O_NOCTTY);
    if (p.fd < 0) {
        asft_error("Cannot open serial port\n");
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
        asft_error("Cannot set serial port attributes\n");
        goto error;
    }
    tcflush(p.fd, TCIOFLUSH);

    // A partial workaround for some crappy USB serial adapters that
    // produce all-zero bytes every read() after first open()
    // if there was already some data in their receive buffer
    // at the moment of first open().
    // Even after second open(), they still do not fully tcflush()
    // previously received data. Expect some garbage after a few
    // first read() calls.
    close(p.fd);
    usleep(10000);
    p.fd = open(devname, O_RDWR | O_NOCTTY);
    if (p.fd < 0) {
        asft_error("Cannot reopen serial port\n");
        goto error;
    }
    tcflush(p.fd, TCIOFLUSH);

    asft_info("Serial port %s %s baud. Maximum frame length %lu bytes.\n",
           devname, baudrate_string, p.frame_tx_len_max);

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

    p.frame_tx_buf[1] = 0;
    frame_len = 1;
    frame_len += cobs_encode(pkt, pkt_len, &p.frame_tx_buf[1]);
    p.frame_tx_buf[frame_len] = 0;
    frame_len++;

    pos = p.frame_tx_buf;
    bytes_remaining = frame_len;
    while (bytes_remaining) {
        bytes_written = write(p.fd, pos, bytes_remaining);
        if (bytes_written > 0) {
            pos += bytes_written;
            bytes_remaining -= bytes_written;
        } else if (bytes_written < 0 && errno != EINTR) {
            asft_error("Serial port write error\n");
            asft_serial_cleanup();
            return -EIO;
        }
    }

    return 0;
}

int asft_serial_receive(unsigned char **buf_ptr, size_t *len_ptr)
{
    bool had_read = false;
    size_t pkt_rx_len;

    *buf_ptr = NULL;
    *len_ptr = 0;

    if (p.fd < 0) {
        return -EIO;
    }

    if (p.bytes_remaining) {
        goto decode;
    }

again:

    had_read = true;
    p.bytes_read = read(p.fd, p.read_buf, sizeof(p.read_buf));
    if(p.bytes_read < 0) {
        if (errno == EINTR) 
            goto again;

        asft_error("Serial port read error\n");
        asft_serial_cleanup();
        return -EIO;
    }
    p.bytes_remaining = p.bytes_read;

decode:

    while (p.bytes_remaining) {
        unsigned char c = p.read_buf[p.bytes_read - p.bytes_remaining];
        p.bytes_remaining--;

        if (c == 0x00) {
            if (p.frame_rx_len) {
                /* Frame received */
                pkt_rx_len = cobs_decode(p.frame_rx_buf, p.frame_rx_len, p.pkt_rx_buf);
                p.frame_rx_len = 0;
                *buf_ptr = p.pkt_rx_buf;
                *len_ptr = pkt_rx_len;
                return 1;
            }
        } else if (p.frame_rx_len > p.frame_rx_len_max) {
            asft_debug("Received frame too long\n");
            p.frame_rx_len = 0;
        } else {
            p.frame_rx_buf[p.frame_rx_len] = c;
            p.frame_rx_len++;
        }
    }

    if (p.bytes_read < sizeof(p.read_buf) && had_read) {
        usleep(20000);
    }

    return 0;
}
