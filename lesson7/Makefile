ipath = $(realpath include)
CC ?= gcc
CFLAGS ?= -Wall -Werror
lpath = $(realpath lib)
slib = $(realpath lib/lib.a)
shlib = $(realpath lib/mylib.so)
export

all: src
	echo $(inc_path)

install: src
	cp -v stc/execitable /usr/local/bin

.PHONY_ lib
lib: 
	make -C lib.c

.PHONY_ src
src:
	make -C src
lib:
	make -C lib
clean: 
	make clean -C src