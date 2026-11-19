CC       = gcc
CFLAGS  ?= -Wall -Werror -std=gnu11
LDLIBS  ?= -lcrypto

TARGET   = asft
SRCS     = $(wildcard *.c)
OBJS     = $(SRCS:.c=.o)
DEPS     = $(OBJS:.o=.d)

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS)

%.o: %.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -MMD -MP -c -o $@ $<

-include $(DEPS)

clean:
	$(RM) $(TARGET) $(OBJS) $(DEPS)
