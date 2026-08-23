CC ?= clang-19

PKG_LIBS := libngtcp2 libngtcp2_crypto_ossl libssl libcrypto

CFLAGS += -Wall -Wextra -g $(shell pkg-config --cflags $(PKG_LIBS))
LDFLAGS += $(shell pkg-config --libs $(PKG_LIBS))

CLIENT_TARGET := quic_client
CLIENT_SRCS := quic.c quic_client.c
CLIENT_OBJS := $(CLIENT_SRCS:.c=.o)

SERVER_TARGET := quic_server
SERVER_SRCS := quic.c quic_server.c
SERVER_OBJS := $(SERVER_SRCS:.c=.o)

ALL_SRCS := $(sort $(CLIENT_SRCS) $(SERVER_SRCS))

all: client server

client: $(CLIENT_TARGET)

server: $(SERVER_TARGET)

$(CLIENT_TARGET): $(CLIENT_OBJS)
	$(CC) $(CLIENT_OBJS) -o $@ $(LDFLAGS)

$(SERVER_TARGET): $(SERVER_OBJS)
	$(CC) $(SERVER_OBJS) -o $@ $(LDFLAGS)

%.o: %.c quic.h
	$(CC) $(CFLAGS) -c $< -o $@

check:
	@for src in $(ALL_SRCS); do \
		$(CC) $(CFLAGS) -fsyntax-only $$src || exit 1; \
	done

clean:
	rm -f $(CLIENT_OBJS) $(SERVER_OBJS) $(CLIENT_TARGET) $(SERVER_TARGET)

.PHONY: all client server check clean
