
CC ?= cc
CFLAGS ?= -O2 -g
LDFLAGS ?=

BIN := build/confparse
SRC := src/confparse.c

.PHONY: all clean

all: $(BIN)

$(BIN): $(SRC) | build
	$(CC) $(CFLAGS) -o $@ $(SRC) $(LDFLAGS)

build:
	mkdir -p build

clean:
	rm -rf build
