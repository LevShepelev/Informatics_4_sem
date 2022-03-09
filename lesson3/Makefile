all: build

build:
	gcc -Wall -Werror -g -c File_server.c
	gcc File_server.o -o File_server
	gcc -Wall -Werror -g -c File_client.c
	gcc File_client.o -o File_client
run: build
	./server