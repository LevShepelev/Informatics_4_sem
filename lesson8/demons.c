#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
int main() {
    int file = open("/home/lev/Informatics_4_sem/lesson8/file.txt", O_CREAT | O_WRONLY, 0666);
    do  {
        write(file, "hello there!\n", strlen("hello there!\n"));
    } while (!sleep(10));
    return 0;
}