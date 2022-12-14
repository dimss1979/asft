#include <stdio.h>
#include <termios.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/file.h>

#include "serial.h"

int fd = -ENOENT;

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

int serial_open(char *devname, char *baudrate_string)
{
    int rv = 0;
    struct termios t;

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
        close(fd);
        fd = -1;
        rv = -EINVAL;
        goto end;
    }
    tcflush(fd, TCIOFLUSH);

end:

    return rv;
}

int serial_write(unsigned char *buf, size_t len)
{
    unsigned char *pos;
    int bytes_written;
    size_t bytes_remaining;

    if (fd < 0) {
        return -EIO;
    }

    pos = buf;
    bytes_remaining = len;
    while (bytes_remaining) {
        bytes_written = write(fd, pos, bytes_remaining);
        if (bytes_written > 0) {
            pos += bytes_written;
            bytes_remaining -= bytes_written;
        } else if (bytes_written < 0 && bytes_written != -EINTR) {
            fprintf(stderr, "Serial port write error\n");
            return bytes_written;
        }
    }

    return len;
}

int serial_read(unsigned char **buf_ptr, size_t *len_ptr)
{
    int bytes_read;
    unsigned char read_buf[100];

    *buf_ptr = NULL;
    *len_ptr = 0;

    if (fd < 0) {
        return -EIO;
    }

again:

    bytes_read = read(fd, read_buf, sizeof(read_buf));
    printf("Read %i bytes\n", bytes_read);
    if (bytes_read > 0) {
        // TODO Process received bytes
        if (bytes_read < sizeof(read_buf) /* TODO && not full frame ^^^ */) {
            usleep(20000); // TODO tune
        }
    } else if(bytes_read == -EINTR) {
        goto again;
    }

    return bytes_read;
}
