#pragma once

#define _XOPEN_SOURCE 600
#define _GNU_SOURCE
#define __USE_BSD
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
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
#include <sys/types.h>          
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <stdarg.h>
#include <poll.h>
#include <sys/prctl.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

#define BUF_SIZE 1000
#define SECRET "Secret"

int print_time();
int init_log(char* path);
void print_log(char* str, ...);
void printf_fd(int fd, char* str, ...);
#define log(fmt, ...) print_log("%s:%d " fmt, __FILE__, __LINE__, ##__VA_ARGS__)
#define log_info(fmt, ...) log("[INFO] " fmt, ##__VA_ARGS__)
#define log_error(fmt, ...) log("[ERROR] " fmt, ##__VA_ARGS__)
#define log_perror(fmt, ...) log_error ("%d %s " fmt, errno, strerror(errno), ##__VA_ARGS__)

int Socket_config(struct sockaddr_in* server, uint16_t port, int socket_type, int setsockopt_option, char is_bind_need, in_addr_t addr);
int Accept_file(char* input, int client_fd, int size, int is_udp, struct sockaddr_in* server);
void* Mycalloc (int size_of_elem, int size);
int Send_file(char* input, int client_fd, int size, int is_udp, struct sockaddr_in* server);
int Encrypt(const char* info, int info_size, char** encrypted_info, FILE* pubKey_file);
int Decrypt(const char* info, int info_size, char** decrypted_info, FILE* privKey_file );

