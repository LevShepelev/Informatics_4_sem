#pragma once

int print_time();
int init_log(char* path);
void print_log(char* str, ...);
void printf_fd(int fd, char* str, ...);
#define log(fmt, ...) print_log("%s:%d " fmt, __FILE__, __LINE__, ##__VA_ARGS__)
#define log_info(fmt, ...) log("[INFO] " fmt, ##__VA_ARGS__)
#define log_error(fmt, ...) log("[ERROR] " fmt, ##__VA_ARGS__)
#define log_perror(fmt, ...) log_error ("%d %s " fmt, errno, strerror(errno), ##__VA_ARGS__)

#define _XOPEN_SOURCE 600
#define _GNU_SOURCE
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#define __USE_BSD
#include <termios.h>
#include <sys/select.h>
#include <sys/ioctl.h>
#include <string.h>
#include <security/pam_appl.h>
#include <security/pam_misc.h>

#include <sys/types.h>
#include <pwd.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>          /* See NOTES */
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <stdarg.h>
#include <poll.h>

#define BUF_SIZE 1000
const char IS_UDP = '0';
const char IS_TCP = '1';
const char NEED_BIND = 1;
const char NOT_NEED_BIND = 2;
const char GET_FILE[10] = "get_file";
const char SEND_FILE[10] = "send_file";
const char READY_TO_ACCEPT[20] = "ready_to_accept";


int socket_config(struct sockaddr_in* server, uint16_t port, int socket_type, int setsockopt_option, char is_bind_need, in_addr_t addr);
int Accept_file(char* input, int client_fd, int size, int is_udp, struct sockaddr_in* server);
void* mycalloc (int size_of_elem, int size);
int Send_file(char* input, int client_fd, int size, int is_udp, struct sockaddr_in* server);

int socket_config(struct sockaddr_in* server, uint16_t port, int socket_type, int setsockopt_option, char is_bind_need, in_addr_t addr) {
    int a = 1;
    server -> sin_family = AF_INET;
    server -> sin_port   = htons(port);
    server -> sin_addr.s_addr = addr;
    int created_socket = socket(AF_INET, socket_type, 0);

    if (created_socket < 0) {
        log_perror("socket");
        exit(EXIT_FAILURE);
    }

    if (setsockopt_option > 0)
        if (setsockopt(created_socket, SOL_SOCKET, setsockopt_option, &a, sizeof(a)) < 0) {
            log_perror("setsockopt");
            exit(EXIT_FAILURE);
        }

    if (is_bind_need == NEED_BIND) 
        if (bind(created_socket, (struct sockaddr*) server, sizeof(*server)) < 0) {
            log_perror("bind port = %hu\n", port);
            exit(EXIT_FAILURE);
        }

    return created_socket;
}

void* mycalloc (int size_of_elem, int size)
    {
    char* mem = (char*) calloc (size, size_of_elem);
    if (mem == NULL) 
        {
        printf("Calloc error\n");
        exit (EXIT_FAILURE);
        }
    return mem;
    }

int Accept_file(char* input, int client_fd, int size, int is_udp, struct sockaddr_in* server) {
    log_info("accept_file\n");
    socklen_t client_len = sizeof(*server);
    char* buf = NULL;
    unsigned message_size = 0;
    if (!is_udp) {
        if (read(client_fd, &message_size, sizeof(unsigned)) < 0) {
            log_perror("read_size\n");
            return -1;
        }
        log_info("get_size message_size = %u\n", message_size);
        buf = (char*) mycalloc(message_size, sizeof(char));
        if (read(client_fd, buf, message_size) < 0) {
            log_perror("recv_message\n");
            return -1;
        }
    }
    else {
        if (recvfrom(client_fd, &message_size, sizeof(unsigned), 0, (struct sockaddr*) &server, &client_len) < 0) {
            log_perror("read_size\n");
            return -1;
        }
        log_info("get_size message_size = %u\n", message_size);
        buf = (char*) mycalloc(message_size, sizeof(char));
        if (recvfrom(client_fd, buf, message_size, 0, (struct sockaddr*) &server, &client_len) < 0) {
            log_perror("recv_message\n");
            return -1;
        }
    }

    char* path_name = strchr(strchr(input, ' ') + 1, ' ') + 1;
    *strchr(input, '\n') = '\0';
    log_info("path_name = %s: end\n", path_name);
    int file_fd = open(path_name, O_CREAT | O_WRONLY | O_TRUNC, 0666);
    if (file_fd < 0) {
        log_perror("open");
        return -1;
    }
    if (write(file_fd, buf, message_size) != message_size) {
        log_perror("write");
        return -1;
    }
    free(buf);
    return 0;
}

int Send_file(char* input, int client_fd, int size, int is_udp, struct sockaddr_in* server) {
    char* path_name = strchr(input, ' ') + 1;
    *strchr(path_name, ' ') = '\0';
    log_info("sending_file %s\n", path_name);
    struct stat statistica;
    int stat_error = stat(path_name, &statistica);
    if (stat_error < 0) {
        printf("No such file\n");
        return -1;
    }

    int file_fd = open(path_name, O_RDONLY);
    if (file_fd < 0) {
        log_perror("open");
        return -1;
    }
    
    char* buf = (char*) mycalloc(statistica.st_size, sizeof(char));
    read(file_fd, buf, statistica.st_size);
    log_info("file %s\n", buf);
    unsigned message_size = statistica.st_size;
    log_info("st_size = %u\n", message_size);
    
    if (is_udp) {
        if (sendto(client_fd, &message_size, sizeof(unsigned), 0, (struct sockaddr*) server, sizeof(*server)) < 0) {
            log_perror("write in Send_file");
            return -1;
        }
        sleep(1);
        if (sendto(client_fd, buf, message_size, 0, (struct sockaddr*) server, sizeof(*server)) < 0) {
            log_perror("write in Send_file");
            return -1;
        }
        log_info("was sended size = %d, mess = %s\n", message_size, buf);
        if (sendto(client_fd, buf, message_size, 0, (struct sockaddr*) server, sizeof(*server)) < 0) {
            log_perror("write in Send_file");
            return -1;
        }
    }
    else {
        if (write(client_fd, &message_size, sizeof(unsigned)) < 0) {
            log_perror("write in Send_file");
            return -1;
        }
        usleep(100000);
        if (write(client_fd, buf, message_size) < 0) {
            log_perror("write in Send_file");
            return -1;
        }
    }
    
    
    log_info("ALL INFO ABOUT FILE SENDED\n");
    free(buf);
    return 0;
}




