#include <sys/types.h>          /* See NOTES */
#include <sys/socket.h>
#include <stdio.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>


int main() {
    int max_clients = 100;
    struct sockaddr_in server;
    struct in_addr tmp;
    tmp.s_addr = htonl(INADDR_ANY);
    server.sin_family = AF_INET;
    server.sin_port   = htons(30000);
    server.sin_addr   = tmp;
    struct sockaddr_in client;
    

    int socket_tcp = socket(AF_INET, SOCK_STREAM, 0);
    perror("socket");
    int reuse = 1;
    setsockopt(socket_tcp, SOL_SOCKET, SO_REUSEADDR, (const char *)&reuse, sizeof(int));
    setsockopt(socket_tcp, SOL_SOCKET, SO_REUSEPORT, (const char *)&reuse, sizeof(int));
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

        int client_fd = accept(socket_tcp, (struct sockaddr*) &client, &client_len);
        perror("accept");

            unsigned message_size = 0;
            recv(client_fd, (char*) &message_size, sizeof(message_size), 0); 
            char* buf = (char*) calloc(message_size, sizeof(char));    
            unsigned path_size = 0;
            recv(client_fd, (char*) &path_size, sizeof(path_size), 0);
            char* path_name = (char*) calloc(path_size, sizeof(char));
            
            if (recv(client_fd, buf, message_size, 0) != message_size)
                perror("recv message");
            if (recv(client_fd, path_name, path_size, 0) != path_size)
                perror("recv path");
            printf("path_name = %s\n", path_name);
            int file_fd = open(path_name, O_WRONLY | O_CREAT | O_TRUNC, 0666);
            if (file_fd < 0) {
                perror("open");
                return -1;
            }
            if (write(file_fd, buf, message_size) != message_size)
                perror("write");
            
        close(socket_tcp);
}