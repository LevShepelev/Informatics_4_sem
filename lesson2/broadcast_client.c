#include <sys/types.h>          
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>

int main()
    {
    int buf_size = 1000;
    struct sockaddr_in server;
    struct in_addr tmp;
    tmp.s_addr = htonl(INADDR_ANY);
    server.sin_family = AF_INET;
    server.sin_port   = htons(80);
    server.sin_addr   = tmp;
    char* buf = (char*) calloc(buf_size, sizeof(char));
    char* buf_receive = (char*) calloc(buf_size, sizeof(char));
    sprintf(buf, "%s", "Hello_Buddy");
    int socket_udp = socket(AF_INET, SOCK_DGRAM, 0);
    perror("socket\n");
    int a = 1;
    setsockopt(socket_udp, SOL_SOCKET, SO_BROADCAST, &a, sizeof(a));      
    sendto(socket_udp, buf, buf_size, 0, (struct sockaddr*) &server, sizeof(server));

    struct sockaddr_in client;
    socklen_t client_len = sizeof(client);
    recvfrom(socket_udp, buf_receive, buf_size, 0, (struct sockaddr*) &client, &client_len);
    printf("%s\n", inet_ntoa((((struct sockaddr_in*) &client)->sin_addr)));
    }