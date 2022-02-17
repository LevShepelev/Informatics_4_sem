all: build

build:
	gcc -Wall -Werror -g -c broadcast_server.c
	gcc broadcast_server.o -o broadcast_server
	gcc -Wall -Werror -g -c broadcast_client.c
	gcc broadcast_client.o -o broadcast_client
run: build
	./server