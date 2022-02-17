#include <sys/types.h>          /* See NOTES */
#include <sys/socket.h>
#include <stdio.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>
int main()
    {
    int is_udp = 0, buf_size = 1000, max_clients = 100;
    printf("To use udp press 1, to use tcp press 0\n");
    scanf("%d", &is_udp);
    struct sockaddr_in server;
    struct in_addr tmp;
    tmp.s_addr = htonl(INADDR_ANY);
    server.sin_family = AF_INET;
    server.sin_port   = htons(30000);
    server.sin_addr   = tmp;
    struct sockaddr_in client;
    char* buf = (char*) calloc(buf_size, sizeof(char));

    if (is_udp == 1) 
        {
        int socket_udp = socket(AF_INET, SOCK_DGRAM, 0);
        perror("socket");
        if (bind(socket_udp, (struct sockaddr*) &server, sizeof(server)) < 0)
            {
            perror("bind");
            exit(1);
            }
        while(1)
            {
            socklen_t client_len = sizeof(client);
            int len = recvfrom(socket_udp, buf, buf_size, 0, (struct sockaddr*) &client, &client_len);
            if (len > 0)
                for (int i = 0; i < len; i++)
                    printf("%c", buf[i]);
            if (len < 0)
                {
                perror("");
                break;
                }
            }
        }
    else if (is_udp == 0)
        {
        int socket_tcp = socket(AF_INET, SOCK_STREAM, 0);
        perror("socket");
        int reuse = 1;
        setsockopt(socket_tcp, SOL_SOCKET, SO_REUSEADDR, (const char *)&reuse, sizeof(int));
        perror("setsocketopt");
   
        if (bind(socket_tcp, (struct sockaddr*) &server, sizeof(server)) < 0)
            {
            perror("bind");
            exit(1);
            }
        if (listen(socket_tcp, max_clients) < 0)
            {
            perror("listen");
            exit(1);
            }
            socklen_t client_len = sizeof(client);
        while (1)
            {
            for (int i = 0; i < max_clients - 1; i++)
                {
                int fork_code = fork();
                if (fork_code == 0)
                    break;
                }
            int client_fd = accept(socket_tcp, (struct sockaddr*) &client, &client_len);
            perror("accept");
            while (1)
                {
                fflush(stdout);
                int len = read(client_fd, buf, buf_size);
                for (int i = 0; i < len; i++)
                    printf("%c", buf[i]);                
                }
            }
        }
    else 
        {
        free(buf);
        printf("incorrect input\n");
        return 0;
        }
    }