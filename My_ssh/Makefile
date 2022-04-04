all:
	gcc -c -g -O0 ssh_client.c 
	gcc -c -g -O0 ssh_server.c
	gcc ssh_client.o -o ssh_client 
	gcc ssh_server.o -o ssh_server -lpam -lpam_misc