all: build

build:
	gcc -Wall -Werror -g -c auth.c -g
	gcc auth.o -o auth -lpam -lpam_misc

run: build
	./auth