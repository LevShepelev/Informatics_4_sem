
#include "../../SSH/lib.h"


int main(int argc, char* argv[])
    {
    int  buf_size = 1000, test = 1;
    struct sockaddr_in server;
    struct in_addr tmp;
    inet_aton(argv[1], &tmp);
    server.sin_family = AF_INET;
    server.sin_port   = htons(30000);
    server.sin_addr   = tmp;
    socklen_t client_len = sizeof(server);
    char* buf = (char*) calloc(buf_size, sizeof(char));

        
        int socket_udp = socket(AF_INET, SOCK_DGRAM, 0);
        sendto(socket_udp, &test, sizeof(int), 0, (struct sockaddr*) &server, sizeof(server));
        perror("socket\n");
        if (!fork()) {
            while(1) {
                fflush(stdin);
                int sz = read(STDIN_FILENO, buf, buf_size);
                sz = sendto(socket_udp, buf, sz, 0, (struct sockaddr*) &server, sizeof(server));
                log_info("was send sz = %d, %s\n", sz, buf);
                
                if (strncmp(buf, SEND_FILE, strlen(SEND_FILE)) == 0) {
                    printf("call Send_file\n");
                    usleep(1000);
                    if (sendto(socket_udp, READY_TO_ACCEPT, strlen(READY_TO_ACCEPT), 0, (struct sockaddr*) &server, sizeof(server)) < 0) {
                        log_perror("write ins Send_file");
                        return -1;
                    }
                    Send_file(buf, socket_udp, sz, 1, &server);
                }
            }
        }
        while(1)
            {
            
            int sz = recvfrom(socket_udp, buf, buf_size, 0, (struct sockaddr*) &server, &client_len);
            log_info("client get sz = %d, buf = %s\n", sz, buf);
            
            if (strncmp(buf, READY_TO_ACCEPT, strlen(READY_TO_ACCEPT)) == 0) {
                Accept_file(buf, socket_udp, sz, 1, &server);
                continue;
            }

            write(STDOUT_FILENO, buf, buf_size);
            for (int i = 0; i < BUF_SIZE; i++)
                buf[i] = '\0';
            
            }
    }
    