#pragma once
#define _XOPEN_SOURCE 600
#define _GNU_SOURCE
#define __USE_BSD
#include <sys/types.h>         
#include <sys/socket.h>
#include <stdio.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>
#include "../lesson6/logs.c"
#include <unistd.h>
#include <pwd.h>
#include <security/pam_appl.h>
#include <security/pam_misc.h>
#include <errno.h>
#include <termios.h>
#include <sys/select.h>
#include <sys/ioctl.h>
#include <string.h>
#include <assert.h>
#include <fcntl.h>



#define COND_ERROR_EXIT(ret, str) do { \
    if (ret < 0) {                \
        log_perror(str);          \
        exit(1);                  \
    }                             \
} while(0)                          

typedef struct message {
    char mess_type;
    unsigned int mess_size;
} mess_t;

enum TYPES_OF_MESSAGES {
    AUTH_REQUEST = 1,
    PASSWORD_REQUEST = 2,
    PASSWORD_MESSAGE = 3,
    AUTH_SUCCESS = 4,
    AUTH_ERROR   = 5,
    AUTH_WRONG_USER = 14,
    AUTH_WRONG_PASSWORD = 6,
    FILE_PATH = 7,
    FILE_BUF = 8,
    FILE_REQUEST = 9,
    FILE_SENDING_SUCCESS = 10,
    PATH_SENDING_SUCCESS = 11,
    COMMAND_REQUEST = 12,
    COMMAND_SUCCESS = 13

};

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