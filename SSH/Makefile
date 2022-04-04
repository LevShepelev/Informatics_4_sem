all:
	gcc -c -g -O0 client.c ../lesson6/logs.c
	gcc -c -g -O0 server.c
	gcc client.o logs.o -o client 
	gcc server.o logs.o -o server -lpam -lpam_misc
	