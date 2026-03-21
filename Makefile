CC ?= gcc
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
MAIN_NAME = ipt2socks

SRCS = src/main.c src/ctx.c src/netutils.c src/socks5.c \
       src/fakedns.c src/fakedns_server.c \
       src/logutils.c src/mempool.c src/udp_proxy.c src/tcp_proxy.c \
       src/udp_lrucache.c

BUILD_MODE := release
CPPFLAGS   := -D_GNU_SOURCE -DXXH_INLINE_ALL -MMD -MP -I./uthash -I./xxhash
CFLAGS     := -std=c99 -Wall -Wextra -Wvla -pthread -fno-strict-aliasing \
              -ffunction-sections -fdata-sections $(EXTRA_CFLAGS)
LDFLAGS    := -pthread -Wl,--gc-sections $(EXTRA_LDFLAGS)
LDLIBS     := -lm

ifeq ($(DEBUG), 1)
    BUILD_MODE := debug
    CPPFLAGS   += -DENABLE_SENDTO_LOG -DFAKEDNS_MRU_STATS
    CFLAGS     += -O0 -g -fsanitize=address,undefined -Wsign-conversion -Wconversion
    LDFLAGS    += -g -fsanitize=address,undefined
else
    CPPFLAGS   += -DNDEBUG
    CFLAGS     += -O3 -flto=auto
    LDFLAGS    += -O3 -flto=auto -s
endif

ifeq ($(STATIC), 1)
    BUILD_MODE := $(BUILD_MODE)-static
    LDFLAGS    += -static
endif

BUILD_DIR := build/$(BUILD_MODE)

MAIN = $(BUILD_DIR)/$(MAIN_NAME)
OBJS = $(patsubst %.c,$(BUILD_DIR)/%.o,$(SRCS)) $(BUILD_DIR)/libev/ev.o
DEPS = $(OBJS:.o=.d)

.PHONY: all install uninstall clean help

all: $(MAIN)

help:
	@echo "Usage: make [TARGET] [OPTIONS]"
	@echo ""
	@echo "Targets:"
	@echo "  all        Build $(MAIN_NAME) (default)"
	@echo "  install    Install $(MAIN_NAME) to \$$(DESTDIR)\$$(BINDIR) (default: $(BINDIR))"
	@echo "  uninstall  Remove $(MAIN_NAME) from \$$(DESTDIR)\$$(BINDIR)"
	@echo "  clean      Remove all build artifacts (build/)"
	@echo "  help       Show this help message"
	@echo ""
	@echo "Options:"
	@echo "  DEBUG=1    Build with debug symbols and sanitizers (default: 0)"
	@echo "  STATIC=1   Link statically (default: 0)"
	@echo "  CC=...     C compiler to use (default: gcc)"
	@echo "  PREFIX=... Installation prefix (default: /usr/local)"
	@echo ""
	@echo "Examples:"
	@echo "  make"
	@echo "  make DEBUG=1"
	@echo "  make STATIC=1"
	@echo "  make install PREFIX=/usr"

$(MAIN): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(BUILD_DIR)/src/%.o: src/%.c
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/libev/ev.o: libev/ev.c
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(CFLAGS) -fno-sanitize=undefined -include src/libev_config.h -w -c $< -o $@

install: all
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 $(MAIN) $(DESTDIR)$(BINDIR)/$(MAIN_NAME)

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(MAIN_NAME)

clean:
	rm -rf build

-include $(DEPS)
