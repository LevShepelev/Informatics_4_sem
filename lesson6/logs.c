#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <time.h>
#include <fcntl.h>
#include <stdarg.h>
#include <errno.h>
#include <string.h>
#include "logs.h"

static int log_fd = -1;
#define BUF_SIZE (1 << 14)
static char buf_log[BUF_SIZE];

int print_time() {

    struct tm* c;
    time_t t;
    t = time(NULL);
    if (t == -1)
        exit(1);

    c = localtime(&t);
    if (!c)
        exit(1);
    return dprintf(log_fd, "%02d.%02d.%d %02d:%02d:%02d ", c -> tm_mday, c -> tm_mon, c -> tm_year, c -> tm_hour, c -> tm_min, c -> tm_sec);
}

int init_log(char* path) {
    static char* default_path = "./log";

    log_fd = open(path ? path : default_path, O_CREAT | O_RDWR | O_APPEND, 0644);
    if (log_fd < 0)
        exit(1);
    print_time();
    return dprintf(log_fd, "My favourite programm version 0x0. Succesfull log init.\n");
}

void print_log(char* str, ...) {
    va_list ap;
    va_start(ap, str);

    if (log_fd < 0)
        init_log(NULL);

    print_time();

    int ret = vsnprintf(buf_log, BUF_SIZE, str, ap);
    write(log_fd, buf_log, ret);

    va_end(ap);
}

void printf_fd(int fd, char* str, ...) {
    va_list ap;
    va_start(ap, str);
    char buf_printf[10000];
    if (fd < 0) {
            printf("no such file\n");
            exit(1);
        }

    int ret = vsnprintf(buf_printf, 10000, str, ap);
    write(fd, buf_printf, ret);

    va_end(ap);
}

// вместо dprintf нужен snprintf из буфера, чтобы было быстрее


