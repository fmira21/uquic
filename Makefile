CC ?= cc

PKG_LIBS := libngtcp2 libngtcp2_crypto_ossl libssl libcrypto

SAN_FLAGS := -fsanitize=address,undefined -fno-omit-frame-pointer

CFLAGS += -Wall -Wextra -O2 -g -MMD -MP $(shell pkg-config --cflags $(PKG_LIBS)) $(EXTRA_CFLAGS)
LDFLAGS += $(shell pkg-config --libs $(PKG_LIBS)) -luring $(EXTRA_LDFLAGS)

CLIENT_TARGET := example_client
CLIENT_SRCS := quic.c uquic.c example_client.c
CLIENT_OBJS := $(CLIENT_SRCS:.c=.o)

SERVER_TARGET := example_server
SERVER_SRCS := quic.c uquic.c example_server.c
SERVER_OBJS := $(SERVER_SRCS:.c=.o)

LIB_OBJS := quic.o uquic.o

TEST_SRCS := tests/bulk_client.c tests/bulk_server.c tests/recv_contract_server.c \
             tests/verify_client.c tests/deaf_server.c tests/error_paths.c
TEST_BINS := $(TEST_SRCS:.c=)

ALL_SRCS := $(sort $(CLIENT_SRCS) $(SERVER_SRCS))
ALL_OBJS := $(sort $(CLIENT_OBJS) $(SERVER_OBJS))
DEPS := $(ALL_OBJS:.o=.d) $(TEST_SRCS:.c=.d)

all: client server

client: $(CLIENT_TARGET)

server: $(SERVER_TARGET)

$(CLIENT_TARGET): $(CLIENT_OBJS)
	$(CC) $(CLIENT_OBJS) -o $@ $(LDFLAGS)

$(SERVER_TARGET): $(SERVER_OBJS)
	$(CC) $(SERVER_OBJS) -o $@ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

check:
	@for src in $(ALL_SRCS); do \
		$(CC) $(CFLAGS) -fsyntax-only $$src || exit 1; \
	done

tests/%: tests/%.c $(LIB_OBJS)
	$(CC) $(CFLAGS) -I. $< $(LIB_OBJS) -o $@ $(LDFLAGS)

testbins: $(TEST_BINS)

test: all $(TEST_BINS)
	@./tests/run.sh

test-slow: all $(TEST_BINS)
	@SLOW=1 ./tests/run.sh

asan:
	@$(MAKE) clean
	@$(MAKE) test-slow EXTRA_CFLAGS="$(SAN_FLAGS)" EXTRA_LDFLAGS="$(SAN_FLAGS)"

clean:
	rm -f $(ALL_OBJS) $(DEPS) $(CLIENT_TARGET) $(SERVER_TARGET) $(TEST_BINS)

-include $(DEPS)

.PHONY: all client server check testbins test test-slow asan clean
