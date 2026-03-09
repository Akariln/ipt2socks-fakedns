CC ?= gcc
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin

CFLAGS = -std=c99 -Wall -Wextra -Wvla -pthread -O3 -flto=auto \
         -fno-strict-aliasing -ffunction-sections -fdata-sections \
         -DNDEBUG -MMD -MP $(EXTRA_CFLAGS)

CFLAGS += -D_GNU_SOURCE

LDFLAGS = -pthread -O3 -flto=auto -Wl,--gc-sections -s $(EXTRA_LDFLAGS)

LDLIBS = -lm

SRCS = src/main.c src/ctx.c src/netutils.c src/socks5.c \
       libev/ev.c src/fakedns.c src/fakedns_server.c src/xxhash.c \
       src/logutils.c src/mempool.c src/udp_proxy.c src/tcp_proxy.c \
       src/udp_lrucache.c

OBJS = $(SRCS:.c=.o)
DEPS = $(SRCS:.c=.d)

MAIN = ipt2socks

.PHONY: all install clean static musl-static debug

all: $(MAIN)

$(MAIN): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

libev/ev.o: libev/ev.c
	$(CC) $(CFLAGS) -w -c $< -o $@

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

debug:
	$(MAKE) clean
	$(MAKE) CFLAGS="-std=c99 -Wall -Wextra -Wvla -pthread -O0 -g \
		-fno-strict-aliasing -MMD -MP -DENABLE_SENDTO_LOG -DFAKEDNS_MRU_STATS \
		-D_GNU_SOURCE -fsanitize=address,undefined $(EXTRA_CFLAGS)" \
		LDFLAGS="-pthread -g -fsanitize=address,undefined $(EXTRA_LDFLAGS)" \
		all

-include $(DEPS)
