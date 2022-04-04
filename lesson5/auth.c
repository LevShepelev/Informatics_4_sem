#define _GNU_SOURCE

#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <pwd.h>
#include <stdlib.h>
#include <security/pam_appl.h>
#include <security/pam_misc.h>


//compile with -lpam -lpam_misc



struct pam_conv my_conv = {
    misc_conv,
    NULL,
};

int login_into_user(char* username){
    pam_handle_t* pam;
    int ret;

    ret = pam_start("myssh", username, &my_conv, &pam);
    if (ret != PAM_SUCCESS){
        printf("Failed pam_start");
        return -1;
    }

    ret = pam_authenticate(pam, 0);
    if (ret != PAM_SUCCESS) {
        printf(" Incorrect password!\n");
        return -1;
    }

    ret = pam_acct_mgmt(pam, 0);
    if (ret != PAM_SUCCESS) {
        printf("User account expired!");
        return -1;
    }

    if (pam_end(pam, ret) != PAM_SUCCESS) {
        printf("Unable to pam_end()\n");
        return -1;
    }

    printf("login succesfull\n");
    return 0;
}

int main (int argc, char** argv) {
    struct  passwd* info;
    int ret;

    if (argc != 2) {
        printf("Correct usage example: ./a.out <username>\n");
        return 1;
    }
    
    info = getpwnam(argv[1]); //достает про пользователя информацию
    if (!info) {
        perror("getpwnam");
        return -1;
    }

    printf("name: %s, uid: %d ", info -> pw_name, info -> pw_uid);

    system("id");

    if (login_into_user(argv[1])) {
        printf("Unseccesfull authentification for user %s\n", argv[1]);
        return -1;
    }
    if (setgid(info -> pw_gid)) {
        perror("setgid");
        return -1;
    }

    ret = setuid(info -> pw_uid);
    if (ret < 0) {
        perror("setuid");
        return -1;
    }

    system("cat /proc/self/status | grep CapEff");

    execlp("id", "id", NULL);
}