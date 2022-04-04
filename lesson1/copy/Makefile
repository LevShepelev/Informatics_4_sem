all: build

build:
	gcc -Wall  -g -c -O0 server.c ../../lesson6/logs.c
	gcc server.o logs.o -o server -lpam -lpam_misc
	gcc -Wall  -g -c -O0 client.c 
	gcc client.o logs.o -o client -lpam -lpam_misc
run: build
	./server