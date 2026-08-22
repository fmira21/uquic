CC ?= clang-19

PKG_LIBS := libngtcp2 libngtcp2_crypto_ossl libssl libcrypto

CFLAGS += -Wall -Wextra -g $(shell pkg-config --cflags $(PKG_LIBS))
LDFLAGS += $(shell pkg-config --libs $(PKG_LIBS))

QUIC_TARGET := quic_main
QUIC_SRCS := quic.c quic_main.c
QUIC_OBJS := $(QUIC_SRCS:.c=.o)

quic: $(QUIC_TARGET)

$(QUIC_TARGET): $(QUIC_OBJS)
	$(CC) $(QUIC_OBJS) -o $@ $(LDFLAGS)

%.o: %.c quic.h
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(QUIC_OBJS) $(QUIC_TARGET)

.PHONY: quic clean
