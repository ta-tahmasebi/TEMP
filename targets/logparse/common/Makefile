CC ?= gcc
CFLAGS ?= -O2
LDFLAGS ?=

all: build/logparse

build/logparse: src/logparse.c src/store.c
	mkdir -p build
	$(CC) $(CFLAGS) src/logparse.c src/store.c -o $@ $(LDFLAGS)

clean:
	rm -rf build
