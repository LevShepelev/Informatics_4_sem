#include "../include/lib.h"
#include "../include/client.h"

int main(int argc, char* argv[]) {
    signal(SIGPIPE, SIG_IGN); 
    struct sockaddr_in server;
    int socket = 0;
    char is_tcp = -1;
    printf("argc = %d\n", argc);
    if (argc != 3) {
        printf("correct usage: ./client -UDP -broadcast\n");
        exit(EXIT_FAILURE);
    }
    if (strncmp(argv[2], "-broadcast", strlen("-broadcast")) == 0) {
        socket = Socket_config(&server, broadcast_port, SOCK_DGRAM, SO_BROADCAST, NOT_NEED_BIND, htonl(INADDR_BROADCAST));
        if (Broadcast_search(socket, &server) == 0)
            return 0;
    }
    else {
        struct in_addr tmp;
        if (inet_aton(argv[2], &tmp) < 0) {
            log_perror("inet_aton\n");
            exit(EXIT_FAILURE);
        }
        socket = Socket_config(&server, broadcast_port, SOCK_DGRAM, 0, NOT_NEED_BIND, tmp.s_addr);
    }

    if (strncmp(argv[1], "-UDP", strlen("-UDP")) == 0)
        is_tcp = IS_UDP;
    else if (strncmp(argv[1], "-TCP", strlen("-TCP")) == 0)
        is_tcp = IS_TCP;

    if (sendto(socket, &is_tcp, sizeof(char), 0, (struct sockaddr*) &server, sizeof(server)) < 0) {
        log_perror("sendto");
        exit(EXIT_FAILURE);
    }
    if (is_tcp == IS_UDP) {
        printf("udp\n");
        UDP_communication(socket);
    }
    else if (is_tcp == IS_TCP) {
        printf("tcp\n");
        TCP_communication(socket);
    } 
    close(socket);        
    return 0;
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
    log_info("wait for port\n");
    recvfrom(broadcast_socket, &port, sizeof(port), 0, (struct sockaddr*) &tmp_addr, &tmp_addr_len);
    struct sockaddr_in server;
    char buf[BUF_SIZE] = {'\0'};
    log_info("server has: port = %d, %s\n", port, inet_ntoa(tmp_addr.sin_addr));
    int socket_tcp = Socket_config(&server, port, SOCK_STREAM, SO_REUSEADDR, NOT_NEED_BIND, ((struct sockaddr_in*) &tmp_addr) -> sin_addr.s_addr);

    if (connect(socket_tcp, (struct sockaddr*) &server, sizeof(server)) < 0) {
        log_perror("connect");
        exit(1);
    }
    Server_verify_request(socket_tcp, &server);
    unsigned key = Send_symmetric_key(socket_tcp, &server);
    log_info("key = %u\n", key);
    int fork_code = fork();
    if (fork_code == 0) {
        Set_child_death_signal();
        struct pollfd socket_fd = {socket_tcp, POLL_IN, 0};
        while (1) {
            int ret = poll(&socket_fd, 1, connection_time);// 10 seconds
            if (ret == -1) {
                log_perror("poll\n");
            }
            else if (ret == 0) {
                printf("Connection lostexit\n");
                log_info("Connection lost\n");
                exit(1);
            } 
            int sz = Read_safe(socket_tcp, buf, 10000, key);
            if (strncmp(buf, READY_TO_ACCEPT, strlen(READY_TO_ACCEPT)) == 0) {
                Accept_file(buf, socket_tcp, sz, 0, &server, key);
                continue;
            }

            if (strncmp(buf, TIME_OUT, strlen(TIME_OUT)) == 0) {
                printf("server time_out\n");
                kill(getppid(), SIGINT);
                return 0;
            }
            write(STDOUT_FILENO, buf, sz);
        }
    }
    
    while (1) {
        int sz = read(STDIN_FILENO, buf, 10000);
                
        if (Write_safe(socket_tcp, buf, sz, key) != sz) {
            log_perror("write\n");
            exit(1);
        }
        log_info("sended: %s\n", buf);

        if (strncmp(buf, EXIT, strlen(EXIT)) == 0) {
                close(socket_tcp);
                return 0;
            } 

        Send_file_sending_message(socket_tcp, buf, &server, sz, 0, key);

        memset(buf, '\0', BUF_SIZE);        
    }
    close(socket_tcp);
    close(broadcast_socket);
    return 0;
}


int UDP_communication(int broadcast_socket) {
    struct sockaddr_in tmp_addr;
    socklen_t tmp_addr_len = sizeof(tmp_addr);
    uint16_t port = 0;

    struct pollfd socket_broadcast_fd = {broadcast_socket, POLL_IN, 0};
    int ret = poll(&socket_broadcast_fd, 1, 10000);// 10 seconds
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
    sendto(socket_udp, (char*) &test, sizeof(int), 0, (struct sockaddr*) &server, sizeof(server));
    Server_verify_request(socket_udp, &server);
    unsigned key = Send_symmetric_key(socket_udp, &server);
    printf("key = %u\n", key);
    if (fork() == 0) {
        Set_child_death_signal();
        while(1) {
            fflush(stdin);
            int sz = read(STDIN_FILENO, buf, BUF_SIZE);
            if (sz < 0) {
                log_perror("read\n");
                exit(EXIT_FAILURE);
            }
            //Symmetric_encrypting(buf, sz, key);
            sz = Sendto_safe(socket_udp, buf, sz, 0, (struct sockaddr*) &server, sizeof(server), key);
            if (sz < 0) {
                log_perror("sendto\n");
                exit(EXIT_FAILURE);
            }

            log_info("was send sz = %d, %s\n", sz, buf);

            if (strncmp(buf, EXIT, strlen(EXIT)) == 0) {
                close(socket_udp);
                kill(getppid(), SIGINT);
                return 0;
            } 

            Send_file_sending_message(socket_udp, buf, &server, sz, 1, key);
        }
    }
    struct pollfd socket_fd = {socket_udp, POLL_IN, 0};
    
    while(1) {
        int ret = poll(&socket_fd, 1, connection_time);// 10 seconds
        if (ret == -1) {
            log_perror("poll\n");
        }
        else if (ret == 0) {
            printf("Connection lost exit\n");
            log_info("Connection lost\n");
            exit(1);
        } 
        int sz = Recvfrom_safe(socket_udp, buf, BUF_SIZE, 0, (struct sockaddr*) &server, &client_len, key);
        log_info("client get sz = %d, buf = %s\n", sz, buf);
        
        if (strncmp(buf, READY_TO_ACCEPT, strlen(READY_TO_ACCEPT)) == 0) {
            Accept_file(buf, socket_udp, sz, 1, &server, key);
            continue;
        }

        if (strncmp(buf, TIME_OUT, strlen(TIME_OUT)) == 0) {
            printf("server time_out\n");
            return 0;
        }

        write(STDOUT_FILENO, buf, BUF_SIZE);
        for (int i = 0; i < BUF_SIZE; i++)
            buf[i] = '\0';
        
    }
}

int Server_verify_request(int socket, struct sockaddr_in* server) {
    char* message = NULL;
    socklen_t client_len = sizeof(server);

    FILE* pubKey_file = fopen("/home/lev/Informatics_4_sem/SSH/src/server_keys/public.key", "rb");
    if (pubKey_file == NULL) {
        log_perror("problem with pubKey_file\n");
        exit(EXIT_FAILURE);
    }
    int mess_size = Encrypt(verify_key, strlen(verify_key), &message, pubKey_file);
    fclose(pubKey_file);
    if (mess_size == -1) {
        log_perror("Server_verify_request\n");
        exit(EXIT_FAILURE);
    }
    log_info("socket = %d, message = %s\n mess_size = %d\n", socket, message, mess_size);
    sleep(1);
    int ret = sendto(socket, message, mess_size, 0, (struct sockaddr*) server, sizeof(*server));
    if (ret != mess_size) {
        log_perror("send\n");
        exit(EXIT_FAILURE);
    }

    ret = recvfrom(socket, message, strlen(verify_key), 0,  (struct sockaddr*) server, &client_len);
    if (strncmp(message, verify_key, strlen(verify_key)) != 0) {
        log_info("server has not been verified\n");
        exit(EXIT_FAILURE);
    }
    
    free(message);
    printf("Server was verified\n");
    return 0;
}


unsigned Send_symmetric_key(int socket, struct sockaddr_in* server) {
    char* message = NULL;
    socklen_t client_len = sizeof(server);
    unsigned  a = rand() % 10;
    unsigned A = ((unsigned) powl(g, a)) % p, B = 0;
    FILE* pubKey_file = fopen("/home/lev/Informatics_4_sem/SSH/src/server_keys/public.key", "rb");
    int mess_size = Encrypt((char*) &A, sizeof(unsigned), &message, pubKey_file);
    if (mess_size == -1) {
        log_perror("Server_verify_request\n");
        exit(EXIT_FAILURE);
    }
    int ret = sendto(socket, message, mess_size, 0, (struct sockaddr*) server, sizeof(*server));
    if (ret != mess_size) {
        log_perror("send\n");
        exit(EXIT_FAILURE);
    }
    free(message);
    char client_key[4096];
    int pub_client_key = open("/home/lev/Informatics_4_sem/SSH/src/client_keys/public.key", O_RDONLY);
    mess_size = read(pub_client_key, client_key, 4096);
    ret = sendto(socket, client_key, mess_size, 0, (struct sockaddr*) server, sizeof(*server));
    if (ret != mess_size) {
        log_perror("send\n");
        exit(EXIT_FAILURE);
    }
    fclose(pubKey_file);

    char encrypted_message[BUF_SIZE];
    ret = recvfrom(socket, encrypted_message, BUF_SIZE, 0,  (struct sockaddr*) server, &client_len);
    if (ret <= 0) {
        log_error("We recved not B\n");
        exit(EXIT_FAILURE);
    }
    FILE* privKey_file = fopen("/home/lev/Informatics_4_sem/SSH/src/client_keys/private.key", "rb");
    ret = Decrypt(encrypted_message, ret, &message, privKey_file);
    if (ret == sizeof(unsigned))
        memcpy(&B, message, ret);
    else {
        log_error("wrong size of message with B (part of symmetric key\n");
        exit(EXIT_FAILURE);
    }
    return ((unsigned) powl(B, a)) % p;
}


int Send_file_sending_message(int socket, char* buf, struct sockaddr_in* server, int sz, int is_udp, int key) {
    if (strncmp(buf, SEND_FILE, strlen(SEND_FILE)) == 0) {
        Send_file(buf, socket, sz, is_udp, server, key);
    }
    return 0;
}


 int Broadcast_search(int socket, struct sockaddr_in* server) {
    if (sendto(socket, &SEARCH, sizeof(char), 0, (struct sockaddr*) server, sizeof(*server)) < 0) {
        log_perror("sendto");
        exit(EXIT_FAILURE);
    }
    int button = 0;
    int time_start = time(NULL);
    struct sockaddr_in tmp_addr;
    socklen_t tmp_addr_len = sizeof(tmp_addr);
    struct pollfd fd_in[1];
    fd_in[0].fd = socket;
    fd_in[0].events = POLLIN;
    while (time(NULL) - time_start < 10) {
        int ret = poll(fd_in, 2, searching_servers_time);
        if (ret == -1) {
            log_perror("poll\n");
            exit(EXIT_FAILURE);
        }
        else if (ret == 0)
            break;
        int port;
        if (recvfrom(socket, &port, sizeof(int), 0, &tmp_addr, &tmp_addr_len) > 0) 
            printf("The server %s was found\n", inet_ntoa(tmp_addr.sin_addr));
        else {
            log_perror("recvfrom\n");
            exit(EXIT_FAILURE);
        }
        printf("If you want to connect press 1, if you want wait for other servers press 0\n");
        scanf("%d", &button);
        if (button == 1)
            return 1;
    }
    return 0;
 }
