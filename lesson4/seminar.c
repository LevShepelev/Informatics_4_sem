#define _GNU_SOURCE

#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <termios.h>
#include <string.h>

int main() {
    char *bash_argv[] = {"sh", NULL};
    struct termios t;
    char buf[2 << 20];
    int ret = 0;
    int master = posix_openpt(O_RDWR | O_NOCTTY);
    if (master < 0) {
        perror("openpt");
        return 1;
    }
    if (grantpt(master)) {
        perror("grantpt");
        return 1;
    }
    if (unlockpt(master)) {
        perror("unlockpt");
        return 1;
    }
    ret = tcgetattr(master, &t);
    if (ret) {
        perror("tcgetattr");
        return 1;
    }

    cfmakeraw(&t);
    ret = tcsetattr(master, TCSANOW, &t);
    ret = fork();
    if (ret == 0) {
        int term;

        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);
        term = open(ptsname(master), O_RDWR);
        if (term < 0) {
            perror("open slave term");
            exit(1);
        }
        dup2(term, STDIN_FILENO);
        dup2(term, STDOUT_FILENO);
        dup2(term, STDERR_FILENO);
        close(master);
        execvp("sh", bash_argv);
    }

    #define LS "ls -la /proc/self/fd\n"

    write(master, LS, sizeof(LS));
    if (ret != sizeof(LS)) {
        perror("write");
        return 1;
    }

    sleep(3);

    ret = read(master, buf, sizeof(buf));
    write(STDOUT_FILENO, buf, ret);
    write(master, "exit", sizeof("exit"));
    wait(NULL);

    while (1) {
        int sz, wr;
        sz = read(STDIN_FILENO, buf, sizeof(buf));
        if (sz < 0) {
            perror("read");
            return 1;
        }

        wr = write(master, buf, sz);
        if (wr != sz) {
            perror("unable to write into master term");
            return 1;
        }
        if (!strncmp(buf, "exit", 4)) 
            break;
        sleep(1);
        sz = read(master, buf, sizeof(buf));
        if (sz < 0) {
            perror("read");
            return 1;
        }
        
        wr = write(STDOUT_FILENO, buf, sz);
        if (wr != sz) {
            perror("write stdout");
            return 1;
        }
    }
    wait(NULL);
    close(master);
    return 0;
}