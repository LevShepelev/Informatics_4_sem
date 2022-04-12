CC ?= gcc
CFLAGS ?= -Wall -g -Werror
ipath = $(realpath include)
lpath = $(realpath lib)
slib = $(realpath lib/mylib.a)
export

all: src

.PHONY: src
src: lib
	make -C src

.PHONY: lib
lib:
	make -C lib

install: src
	cp src/server /home/lev/tmp/bin/
	cp src/client /home/lev/tmp/bin/
	cp lib/libmylib.so /home/lev/tmp/lib/

uninstall:
	rm -rf /home/lev/tmp/bin/client
	rm -rf /home/lev/tmp/bin/server
	rm -rf /home/lev/tmp/lib/libmylib.so

clean:
	make clean -C src
	make clean -C lib

