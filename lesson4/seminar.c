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
    if (ret) {
		perror("tcsetattr");
		return 1;
	}

    ret = fork();
    if (ret == 0) {

        setgid(0);

        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);
        int term = open(ptsname(master), O_RDWR);
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

    int sz = read(STDIN_FILENO, buf, sizeof(buf));
    if (sz < 0) {
        perror("read");
        return 1;
    }

    ret = write(master, buf, strlen(buf));
    if (ret != strlen(buf)) {
        perror("write");
        return 1;
    }
    /*#define EXIT "exit\n"
	ret = write(master, EXIT, strlen(EXIT));
	if (ret != strlen(EXIT)) {
		perror("unable to write into master term");
		return 1;
	}*/
    printf("waiting\n");
    sleep(1);
    

    ret = read(master, buf, sizeof(buf));
    write(STDOUT_FILENO, buf, ret);
    
    while (1) {
        int sz, wr;
        //ret = read(STDIN_FILENO, buf, sizeof(buf));
        perror("read_sec_mess\n");
        printf("%s", buf);
        sleep(3);
        write(STDOUT_FILENO, "here\n", strlen("here\n"));
        if (sz < 0) {
            perror("read_from_stdin");
            return 1;
        }
        
        sz = read(STDIN_FILENO, buf, sizeof(buf)); //here crash ?
        wait(NULL);
        wr = write(master, buf, sz);
        if (wr != sz) {
            perror("unable to write into master term");
            return 1;
        }
        wait(NULL);
        if (!strncmp(buf, "exit", 4)) 
            break;
        sleep(1);
        sz = read(master, buf, sizeof(buf));
        if (sz < 0) {
            perror("read_form_master");
            return 1;
        }
        
        wr = write(STDOUT_FILENO, buf, sz);
        if (wr != sz) {
            perror("write stdout");
            return 1;
        }
    #define EXIT "exit\n"
        ret = write(master, EXIT, strlen(EXIT));
        if (ret != strlen(EXIT)) {
		perror("unable to write into master term");
		return 1;
        }
    }
    wait(NULL);
    write(master, "exit", sizeof("exit"));
    close(master);
    return 0;
}