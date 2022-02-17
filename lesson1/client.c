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
    int is_udp = 0, buf_size = 1000;
    struct sockaddr_in server;
    struct in_addr tmp;
    tmp.s_addr = htonl(INADDR_LOOPBACK);
    server.sin_family = AF_INET;
    server.sin_port   = htons(30000);
    server.sin_addr   = tmp;
    char* buf = (char*) calloc(buf_size, sizeof(char));
    printf("To use udp press 1, to use tcp press 0\n");
    scanf("%d", &is_udp);
    if (is_udp == 1) 
        {
        int socket_udp = socket(AF_INET, SOCK_DGRAM, 0);
        perror("socket\n");
        while(1)
            {
            fflush(stdin);
            fgets(buf, buf_size, stdin);
            sendto(socket_udp, buf, buf_size, 0, (struct sockaddr*) &server, sizeof(server));
            }
        }
    else if (is_udp == 0)
        {
        int socket_tcp = socket(AF_INET, SOCK_STREAM, 0);
        perror("socket");
        int reuse = 1;
        setsockopt(socket_tcp, SOL_SOCKET, SO_REUSEADDR, (const char *)&reuse, sizeof(int));
        perror("setsocketopt");
        bind(socket_tcp, (struct sockaddr*) &server, sizeof(server));
        connect(socket_tcp, (struct sockaddr*) &server, sizeof(server));
        while (1)
            {
            fflush(stdin);
            fgets(buf, buf_size, stdin);
            //printf("%s, %ld", buf, write(socket_tcp, buf, strlen(buf)));
            write(socket_tcp, buf, strlen(buf));
            }
        }
    else 
        {
        free(buf);
        printf("incorrect input\n");
        return 0;
        }
    }