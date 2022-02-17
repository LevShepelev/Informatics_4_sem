all: build

build:
	gcc -Wall -Werror -g -c server.c
	gcc server.o -o server
	gcc -Wall -Werror -g -c client.c
	gcc client.o -o client
run: build
	./server