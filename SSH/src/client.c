#include "../include/lib.h"
#include "../include/client.h"

int main() {
    signal(SIGPIPE, SIG_IGN); 
    struct sockaddr_in server;
    int broadcast_socket = Socket_config(&server, broadcast_port, SOCK_DGRAM, SO_BROADCAST, NOT_NEED_BIND, htonl(INADDR_BROADCAST));
    printf("if udp press 0, if tcp press 1\n");
    char is_tcp = 0;
    scanf("%c", &is_tcp);
    if (is_tcp == IS_UDP) {
        printf("udp\n");
        if (sendto(broadcast_socket, &is_tcp, sizeof(char), 0, (struct sockaddr*) &server, sizeof(server)) < 0)
            log_perror("sendto\n");
        UDP_communication(broadcast_socket);
    }
    else if (is_tcp == IS_TCP) {
        printf("tcp\n");
        if (sendto(broadcast_socket, &is_tcp, sizeof(char), 0, (struct sockaddr*) &server, sizeof(server)) < 0)
            log_perror("sendto");
        TCP_communication(broadcast_socket);
    }         
}

int TCP_communication(int broadcast_socket) {
    struct sockaddr_in tmp_addr;
    socklen_t tmp_addr_len = sizeof(tmp_addr);
    uint16_t port = 0;

    struct pollfd socket_fd = {broadcast_socket, POLL_IN, 0};
    int ret = poll(&socket_fd, 1, 10000);// 10 seconds
    if (ret == -1) {
        log_perror("poll\n");
    }
    else if (ret == 0) {
        printf("No servers, exit\n");
        log_info("No servers\n");
        exit(1);
    } 

    recvfrom(broadcast_socket, &port, sizeof(port), 0, (struct sockaddr*) &tmp_addr, &tmp_addr_len);

    struct sockaddr_in server;
    char buf[BUF_SIZE] = {'\0'};
    log_info("server has: %s\n", inet_ntoa(tmp_addr.sin_addr));
    int socket_tcp = Socket_config(&server, port, SOCK_STREAM, SO_REUSEADDR, NOT_NEED_BIND, ((struct sockaddr_in*) &tmp_addr) -> sin_addr.s_addr);

    if (connect(socket_tcp, (struct sockaddr*) &server, sizeof(server)) < 0) {
        log_perror("connect");
        exit(1);
    }

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
        int sz = read(STDIN_FILENO, buf, 10000);
        if (strncmp(buf, "exit", 4) == 0)
            break;
                
        if (write(socket_tcp, buf, sz) != sz) {
            log_perror("write\n");
            exit(1);
        }
        log_info("sended: %s\n", buf);

        if (strncmp(buf, SEND_FILE, strlen(SEND_FILE)) == 0) {
            usleep(1000);
            if (write(socket_tcp, READY_TO_ACCEPT, strlen(READY_TO_ACCEPT)) < 0) {
                log_perror("write ins Send_file");
                return -1;
            }
            Send_file(buf, socket_tcp, sz, 0, 0);
        }
        
    }
    close(socket_tcp);
    close(broadcast_socket);
    return 0;
    }


int UDP_communication(int broadcast_socket) {
    struct sockaddr_in tmp_addr;
    socklen_t tmp_addr_len = sizeof(tmp_addr);
    uint16_t port = 0;

    struct pollfd socket_fd = {broadcast_socket, POLL_IN, 0};
    int ret = poll(&socket_fd, 1, 10000);// 10 seconds
    if (ret == -1) {
        log_perror("poll\n");
    }
    else if (ret == 0) {
        printf("No servers, exit\n");
        log_info("No servers\n");
        exit(1);
    } 
    recvfrom(broadcast_socket, &port, sizeof(port), 0, (struct sockaddr*) &tmp_addr, &tmp_addr_len);
    log_info("port = %d\n", port);
    int test = 1;
    struct sockaddr_in server;
    socklen_t client_len = sizeof(server);
    char* buf = (char*) Mycalloc(BUF_SIZE, sizeof(char));

    int socket_udp = Socket_config(&server, port, SOCK_DGRAM, SO_REUSEADDR, NOT_NEED_BIND, ((struct sockaddr_in*) &tmp_addr) -> sin_addr.s_addr);
    sendto(socket_udp, &test, sizeof(int), 0, (struct sockaddr*) &server, sizeof(server));
    if (!fork()) {
        while(1) {
            fflush(stdin);
            int sz = read(STDIN_FILENO, buf, BUF_SIZE);
            sz = sendto(socket_udp, buf, sz, 0, (struct sockaddr*) &server, sizeof(server));
            log_info("was send sz = %d, %s\n", sz, buf);
            
            if (strncmp(buf, SEND_FILE, strlen(SEND_FILE)) == 0) {
                usleep(1000);
                if (sendto(socket_udp, READY_TO_ACCEPT, strlen(READY_TO_ACCEPT), 0, (struct sockaddr*) &server, sizeof(server)) < 0) {
                    log_perror("write ins Send_file");
                    return -1;
                }
                Send_file(buf, socket_udp, sz, 1, &server);
            }
        }
    }

    while(1) {
        int sz = recvfrom(socket_udp, buf, BUF_SIZE, 0, (struct sockaddr*) &server, &client_len);
        log_info("client get sz = %d, buf = %s\n", sz, buf);
        
        if (strncmp(buf, READY_TO_ACCEPT, strlen(READY_TO_ACCEPT)) == 0) {
            Accept_file(buf, socket_udp, sz, 1, &server);
            continue;
        }

        write(STDOUT_FILENO, buf, BUF_SIZE);
        for (int i = 0; i < BUF_SIZE; i++)
            buf[i] = '\0';
        
    }
}