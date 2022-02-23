#include <sys/types.h>          /* See NOTES */
#include <sys/socket.h>
#include <stdio.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>
int main() {
    int buf_size = 1000, a = 1;
    struct sockaddr_in server;
    struct in_addr tmp;
    tmp.s_addr = htonl(INADDR_ANY);
    server.sin_family = AF_INET;
    server.sin_port   = htons(80);
    server.sin_addr   = tmp;
    struct sockaddr_in client;
    char* buf = (char*) calloc(buf_size, sizeof(char));
    int socket_udp = socket(AF_INET, SOCK_DGRAM, 0);
    setsockopt(socket_udp, SOL_SOCKET, SO_BROADCAST, &a, sizeof(a));
    perror("socket");
    if (bind(socket_udp, (struct sockaddr*) &server, sizeof(server)) < 0) {
        perror("bind");
        exit(1);
    }

    socklen_t client_len = sizeof(client);
        int len = recvfrom(socket_udp, buf, buf_size, 0, (struct sockaddr*) &client, &client_len);
        if (len < 0) {
            perror("recvfrom");
            return -1;
        
        printf("%s\n", buf);
        printf("Msg from: %d\n", ntohs(client.sin_port));
        sendto(socket_udp, buf, buf_size, 0, (struct sockaddr*) &client, sizeof(client));
    }
        
}