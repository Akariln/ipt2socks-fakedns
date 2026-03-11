CC ?= gcc
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin

CFLAGS = -std=c99 -Wall -Wextra -Wvla -pthread -O3 -flto=auto \
         -fno-strict-aliasing -ffunction-sections -fdata-sections \
         -DNDEBUG -MMD -MP \
         -I./uthash -I./xxhash \
         $(EXTRA_CFLAGS)

CFLAGS += -D_GNU_SOURCE

LDFLAGS = -pthread -O3 -flto=auto -Wl,--gc-sections -s $(EXTRA_LDFLAGS)

LDLIBS = -lm

SRCS = src/main.c src/ctx.c src/netutils.c src/socks5.c \
       src/fakedns.c src/fakedns_server.c \
       src/logutils.c src/mempool.c src/udp_proxy.c src/tcp_proxy.c \
       src/udp_lrucache.c

OBJS = $(SRCS:.c=.o) xxhash/xxhash.o libev/ev.o
DEPS = $(SRCS:.c=.d) xxhash/xxhash.d libev/ev.d

MAIN = ipt2socks

.PHONY: all install clean static musl-static debug

all: $(MAIN)

$(MAIN): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

libev/ev.o: libev/ev.c
	$(CC) $(CFLAGS) -fno-sanitize=undefined -include src/libev_config.h -w -c $< -o $@

xxhash/xxhash.o: xxhash/xxhash.c
	$(CC) $(CFLAGS) -c $< -o $@

install: $(MAIN)
	mkdir -p $(DESTDIR)$(BINDIR)
	cp -f $(MAIN) $(DESTDIR)$(BINDIR)/$(MAIN)
	chmod 755 $(DESTDIR)$(BINDIR)/$(MAIN)

clean:
	rm -f $(MAIN) $(OBJS) $(DEPS)

static:
	$(MAKE) clean
	$(MAKE) LDFLAGS="-pthread -O3 -flto=auto -Wl,--gc-sections -s -static $(EXTRA_LDFLAGS)" \
		all

musl-static:
	$(MAKE) clean
	$(MAKE) CC=musl-gcc \
		LDFLAGS="-pthread -O3 -flto=auto -Wl,--gc-sections -s -static $(EXTRA_LDFLAGS)" \
		all

debug:
	$(MAKE) clean
	$(MAKE) CFLAGS="-std=c99 -Wall -Wextra -Wvla -pthread -O0 -g \
		-fno-strict-aliasing -MMD -MP -DENABLE_SENDTO_LOG -DFAKEDNS_MRU_STATS \
		-D_GNU_SOURCE -I./uthash -I./xxhash -fsanitize=address,undefined $(EXTRA_CFLAGS)" \
		LDFLAGS="-pthread -g -fsanitize=address,undefined $(EXTRA_LDFLAGS)" \
		all

-include $(DEPS)
