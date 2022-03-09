#include <sys/types.h>          
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <assert.h>


int main(int argc, char* argv[]) {
    struct sockaddr_in server;
    struct in_addr tmp;
    if (inet_aton(argv[2], &tmp) == 0) {
        perror("wrong ip");
        return -1;
    }
    server.sin_family = AF_INET;
    server.sin_port   = htons(30000);
    server.sin_addr   = tmp;

    int file_fd = open(argv[1], O_RDONLY);
    if (file_fd < 0) {
        perror("open");
        return -1;
    }
    struct stat statistica;
    int stat_error = stat (argv[1], &statistica);
    assert(stat_error == 0);

    char* buf = (char*) calloc(statistica.st_size, sizeof(char));
    read(file_fd, buf, statistica.st_size);

    int socket_tcp = socket(AF_INET, SOCK_STREAM, 0);
    perror("socket");
    int reuse = 1;
    setsockopt(socket_tcp, SOL_SOCKET, SO_REUSEADDR, (const char *)&reuse, sizeof(int));
    perror("setsocketopt");
    bind(socket_tcp, (struct sockaddr*) &server, sizeof(server));
    connect(socket_tcp, (struct sockaddr*) &server, sizeof(server));
    unsigned message_size = statistica.st_size;

    send(socket_tcp, (char*) &message_size, sizeof(message_size), 0);
    message_size = strlen(argv[3]);
    send(socket_tcp, (char*) &message_size, sizeof(message_size), 0);
    send(socket_tcp, buf, statistica.st_size, 0);
    send(socket_tcp, argv[3], strlen(argv[3]), 0);
    return 0;
}