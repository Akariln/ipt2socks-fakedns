CC ?= gcc
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin

CFLAGS = -std=c99 -Wall -Wextra -Wvla -pthread -O3 -flto=auto \
         -fno-strict-aliasing -ffunction-sections -fdata-sections \
         -DNDEBUG -MMD -MP $(EXTRA_CFLAGS)

LDFLAGS = -pthread -O3 -flto=auto -fno-strict-aliasing -Wl,--gc-sections -s $(EXTRA_LDFLAGS)

LDLIBS = -lm

SRCS = src/main.c src/ctx.c src/lrucache.c src/netutils.c src/socks5.c \
       libev/ev.c src/fakedns.c src/xxhash.c src/logutils.c src/mempool.c \
       src/udp_proxy.c src/tcp_proxy.c

OBJS = $(SRCS:.c=.o)
DEPS = $(SRCS:.c=.d)

MAIN = ipt2socks

.PHONY: all install clean static musl-static

all: $(MAIN)

$(MAIN): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

install: $(MAIN)
	mkdir -p $(DESTDIR)$(BINDIR)
	install -m 0755 $(MAIN) $(DESTDIR)$(BINDIR)

clean:
	$(RM) $(MAIN) $(OBJS) $(DEPS)

static: $(OBJS)
	$(CC) $(LDFLAGS) -static -o $(MAIN) $(OBJS) $(LDLIBS)

musl-static:
	$(MAKE) clean
	$(MAKE) CC=musl-gcc static

-include $(DEPS)
