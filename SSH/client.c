#include "lib.h"

int TCP_communication(int broadcast_socket);
int UDP_communication(int broadcast_socket);
const int udp_port = 29435;
const uint16_t broadcast_port = 29747;

int main(int argc, char* argv[]) {
    signal(SIGPIPE, SIG_IGN); 
    struct sockaddr_in server;
    struct in_addr tmp;
    
    server.sin_family      = AF_INET;
    server.sin_port        = htons(broadcast_port);
    server.sin_addr.s_addr = htonl(INADDR_BROADCAST);
    char buf_receive[BUF_SIZE];
    int broadcast_socket = socket(AF_INET, SOCK_DGRAM, 0);
    perror("socket\n");
    int a = 1;
    setsockopt(broadcast_socket, SOL_SOCKET, SO_BROADCAST, &a, sizeof(a));
    printf("if udp press 0, if tcp press 1\n");
    char is_tcp = 0;
    scanf("%c", &is_tcp);
    printf("is_tcp = %c\n", is_tcp);
    if (is_tcp == IS_UDP) {
        printf("udp\n");
        if (sendto(broadcast_socket, &is_tcp, sizeof(char), 0, (struct sockaddr*) &server, sizeof(server)) < 0)
            perror("sendto\n");
        UDP_communication(broadcast_socket);
    }
    else if (is_tcp == IS_TCP) {
        printf("tcp\n");
        if (sendto(broadcast_socket, &is_tcp, sizeof(char), 0, (struct sockaddr*) &server, sizeof(server)) < 0)
            perror("sendto");
        TCP_communication(broadcast_socket);
    }         
}

int TCP_communication(int broadcast_socket) {
    struct sockaddr_in tmp_addr;
    socklen_t tmp_addr_len = sizeof(tmp_addr);
    uint16_t port = 0;
    log_info("waiting for answer broadcast\n");
    recvfrom(broadcast_socket, &port, sizeof(port), 0, (struct sockaddr*) &tmp_addr, &tmp_addr_len);
    printf("get message back %u: %s\n", port, inet_ntoa(tmp_addr.sin_addr));

    struct sockaddr_in server;
    char* buf = (char*) calloc(BUF_SIZE,  sizeof(char));
    printf("server has: %s\n", inet_ntoa(tmp_addr.sin_addr));
    int socket_tcp = socket_config(&server, port, SOCK_STREAM, SO_REUSEADDR, NOT_NEED_BIND, ((struct sockaddr_in*) &tmp_addr) -> sin_addr.s_addr);

    if (connect(socket_tcp, (struct sockaddr*) &server, sizeof(server)) < 0) {
        log_perror("connect");
        exit(1);
    }

    printf("before fork\n");
    int fork_code = fork();
    if (fork_code == 0) {
        while (1) {
            int sz = read(socket_tcp, buf, 10000);
            if (strncmp(buf, READY_TO_ACCEPT, strlen(READY_TO_ACCEPT)) == 0) {
                Accept_file(buf, socket_tcp, sz, 0, &server);
                continue;
            }
        
            write(STDOUT_FILENO, buf, sz);
        }
    }
    
    while (1) {
        
        fflush(stdin);
        int sz = read(STDIN_FILENO, buf, 10000);
        if (strncmp(buf, "exit", 4) == 0)
            break;
        
        
        printf("was written:\n");
        if (write(STDOUT_FILENO, buf, sz) < 0) {
            log_perror("write\n");
            exit(1);
        }
        //printf("%s, %ld", buf, write(socket_tcp, buf, strlen(buf)));
        if (write(socket_tcp, buf, sz) != sz) {
            log_perror("write\n");
            exit(1);
        }

        if (strncmp(buf, SEND_FILE, strlen(SEND_FILE)) == 0) {
            printf("call Send_file\n");
            usleep(100000);
            if (write(socket_tcp, READY_TO_ACCEPT, strlen(READY_TO_ACCEPT)) < 0) {
                log_perror("write ins Send_file");
                return -1;
            }
            Send_file(buf, socket_tcp, sz, 0, 0);
        }
        
    }
    close(socket_tcp);
    close(broadcast_socket);
    free(buf);
    return 0;
    }

int UDP_communication(int broadcast_socket) {
    struct sockaddr_in tmp_addr;
    socklen_t tmp_addr_len = sizeof(tmp_addr);
    uint16_t port = 0;
    printf("waiting for answer broadcast\n");
    //receive port of tmp_addr
    recvfrom(broadcast_socket, &port, sizeof(port), 0, (struct sockaddr*) &tmp_addr, &tmp_addr_len);
    log_info("port = %d", port);
    int  buf_size = 1000, test = 1;
    struct sockaddr_in server;
    socklen_t client_len = sizeof(server);
    char* buf = (char*) calloc(buf_size, sizeof(char));

    int socket_udp = socket_config(&server, port, SOCK_DGRAM, SO_REUSEADDR, NOT_NEED_BIND, ((struct sockaddr_in*) &tmp_addr) -> sin_addr.s_addr);
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