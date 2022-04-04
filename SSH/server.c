
#include "lib.h"


int TCP_communication(int socket_tcp);
int UDP_communication(int socket_udp, struct sockaddr_in* client);

const uint16_t tcp_port = 30037;
const uint16_t broadcast_port = 29747;
const uint16_t udp_port_first = 25001;
#define MAX_CLIENTS 100

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


int main() { 
    /*int file_fd = open("main", O_CREAT | O_WRONLY | O_TRUNC, 0666);
    if (file_fd < 0) {
        log_perror("open");
        return -1;
    }*/
    signal(SIGPIPE, SIG_IGN); 
    char buf[BUF_SIZE];
    struct sockaddr_in client;
    int a = 1;
    uint16_t udp_port_counter = 0;
    struct sockaddr_in broadcast_server;
    int socket_broadcast = socket_config(&broadcast_server, broadcast_port, SOCK_DGRAM, SO_BROADCAST, NEED_BIND, htonl(INADDR_BROADCAST));
    if (setsockopt(socket_broadcast, SOL_SOCKET, SO_REUSEADDR, &a, sizeof(a)) < 0) {
        log_perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in tcp_server;
    struct sockaddr_in udp_server;

    int socket_tcp = socket_config(&tcp_server, tcp_port, SOCK_STREAM, SO_REUSEADDR, NEED_BIND, htonl(INADDR_ANY));
    if (listen(socket_tcp, MAX_CLIENTS) < 0) {
        log_perror("listen");
        return 1;
    }

    perror("socket\n");
    while (1){
        socklen_t client_len = sizeof(client);
        int len = recvfrom(socket_broadcast, buf, BUF_SIZE, 0, (struct sockaddr*) &client, &client_len);
         if (len < 0) {
            log_perror("recvfrom");
            return -1;
        }

        printf("Msg from: %d\n", ntohs(client.sin_port));
        printf("buf = %s\n", buf);
       
        int fork_code = fork();
        if (fork_code != 0) {
            
            if (buf[0] == IS_UDP) {
                uint16_t free_udp_port = udp_port_first + udp_port_counter;
                                //printf("want server_my_addr_and_port, %s, %hu", inet_ntoa(udp_server.sin_addr), free_udp_port);

                if (sendto(socket_broadcast, &free_udp_port, sizeof(free_udp_port), 0, (struct sockaddr*) &client, sizeof(client)) < 0) {
                    log_perror("sendto");
                    exit(EXIT_FAILURE);
                }
                struct sockaddr_in server;
                int socket_udp = socket_config(&server, free_udp_port, SOCK_DGRAM, SO_REUSEADDR, NEED_BIND, htonl(INADDR_ANY));

                if (udp_port_counter > 100) {
                    log_error("too much udp clients\n");
                    exit(EXIT_FAILURE);
                }

                UDP_communication(socket_udp, &client);
            }
                
        }
        else if (buf[0] == IS_TCP) {
            sendto(socket_broadcast, &tcp_port, sizeof(tcp_port), 0, (struct sockaddr*) &client, sizeof(client));
            log_info("port_sended\n");
            TCP_communication(socket_tcp);
        }
    }        
}
    
    

int TCP_communication(int socket_tcp) {
    printf("tcp_communication\n");
    int is_clients = 1;
    struct sockaddr_in client;
    socklen_t client_len = sizeof(client);
    log_info("listening...\n");
    int client_fd = accept(socket_tcp, (struct sockaddr*) &client, &client_len); 
    if (client_fd < 0) {
        log_perror("accept");
        return 1;
    }
    int fdm, fds;
    int rc = 0, cur_sock_buf_size = 0;
    char input[BUF_SIZE] = {'\0'};
    int auth = 1;

    fdm = posix_openpt(O_RDWR);
    if (fdm < 0) {
        log_perror("Error on posix_openpt()\n");
        return 1;
    }

    rc = grantpt(fdm);
    if (rc != 0) {
        log_perror("Error on grantpt()\n");
        return 1;
    }

    rc = unlockpt(fdm);
    if (rc != 0)  {
        log_perror("Error on unlockpt()\n");
        return 1;
    }

    // Open the slave side ot the PTY
    fds = open(ptsname(fdm), O_RDWR);

    // Create the child process
    if (fork()) {
        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        dup(client_fd);
        dup(client_fd);
        // Close the slave side of the PTY
        close(fds);
        struct pollfd fds[2];
        while (1) {
            // Wait for data from standard input and master side of PTY

            //int largest_sock = fdm > client_fd ? fdm : client_fd;
            
 
            fds[0].fd = client_fd;
            fds[0].events = POLLIN;
            
            fds[1].fd = fdm;
            fds[1].events = POLLIN;
            
            int ret = poll(fds, 2, -1);
            if (ret == -1) {
                log_perror("poll");
                exit(EXIT_FAILURE);
            }
            
            /*rc = select(fdm + 1, &fd_in, NULL, NULL, NULL);
            if (rc < 0) {
                log_perror("Error on select()\n");
                return 1;
            }*/
                    // If data on standard input
            if (auth) {
                struct  passwd* info;
                int ret;
                char buf[4096];
                printf("write name of user\n");
                read(0, buf, 4096);
                for (int i = 0; i < strlen(buf); i++)
                  if (buf[i] == '\n') buf[i] = '\0';
                printf("user = %s\n", buf);
                info = getpwnam(buf); //достает про пользователя информацию
                if (!info) {
                    log_perror("getpwnam");
                    return -1;
                }
                if (login_into_user(buf)) {
                  //write(STDOUT_FILENO, )
                    printf("Unseccesfull authentification for user %s\n", buf);
                    return -1;
                }
                if (setgid(info -> pw_gid)) {
                    log_perror("setgid");
                    return -1;
                }

                ret = setuid(info -> pw_uid);
                if (ret < 0) {
                    log_perror("setuid");
                    return -1;
                }
                auth = 0;
            }

            if (fds[0].revents & POLLIN)  {
                fds[0].revents = 0;
                log_info("standard input\n");
                rc = read(client_fd, input, BUF_SIZE);
                if (rc == 0)
                    return 0;
                log_info("rc = %d\n", rc);
                sleep(1);
                log_info("get: %s\n", input);
                if (rc > 0) {
                    if (strncmp(input, SEND_FILE, strlen(SEND_FILE)) == 0) {
                        char message[20];
                        log_info("wait READY_TO_ACCEPT\n");
                        rc = read(client_fd, message, strlen(READY_TO_ACCEPT));
                        if (rc < 0) {
                            log_perror("read\n");
                            return -1;
                        }
                        log_info("message = %s\n", message);
                        if (strncmp(message, READY_TO_ACCEPT, strlen(READY_TO_ACCEPT)) == 0)
                            Accept_file(input, client_fd, rc, 0, NULL);
                        continue;
                    }

                    if (strncmp(input, GET_FILE, strlen(GET_FILE)) == 0) {
                        printf("call Send_file\n");
                        if (write(client_fd, READY_TO_ACCEPT, strlen(READY_TO_ACCEPT)) < 0) {
                            log_perror("write ins Send_file");
                            return -1;
                        }
                        sleep(1);
                        Send_file(input, client_fd, rc, 0, 0);
                        continue;
                    }

                    write(fdm, input, rc);
                }
                else if (rc < 0) {
                    log_perror("Error on read standard input\n");
                    return(1);
                }
            }

            if (fds[1].revents & POLLIN) {
                fds[1].revents = 0;
                log_info("master_side\n");
                rc = read(fdm, input, BUF_SIZE);
                //for (int i = 0; i < rc; i++)
                    //printf("%d '%c', ", input[i], input[i]);
                write(client_fd, input, rc);
            }     
        }
    }
    else {
        struct termios slave_orig_term_settings; // Saved terminal settings
        struct termios new_term_settings; // Current terminal settings

        // Close the master side of the PTY
        close(fdm);

        // Save the defaults parameters of the slave side of the PTY
        rc = tcgetattr(fds, &slave_orig_term_settings);

        // Set RAW mode on slave side of PTY
        new_term_settings = slave_orig_term_settings;
        cfmakeraw (&new_term_settings);
        tcsetattr (fds, TCSANOW, &new_term_settings);

        // The slave side of the PTY becomes the standard input and outputs of the child process
        close(STDERR_FILENO);
        close(STDIN_FILENO);
        close(STDOUT_FILENO); 

        dup(fds); // PTY becomes standard input (0)
        dup(fds); // PTY becomes standard output (1)
        dup(fds); // PTY becomes standard error (2)

        // Now the original file descriptor is useless
        close(fds);

        // Make the current process a new session leader
        setsid();

        // As the child is a session leader, set the controlling terminal to be the slave side of the PTY
        // (Mandatory for programs like the shell to make them manage correctly their outputs)
        ioctl(0, TIOCSCTTY, 1);

        // Execution of the program
        char *bash_argv[] = {"sh", NULL};
        execvp("sh", bash_argv);

        return 1;
    }
    return 0;
}

int UDP_communication(int socket_udp, struct sockaddr_in* client) {
    int fd[2];
    pipe(fd);
    socklen_t client_len = sizeof(*client); 
    int fdm, fds;
    int rc = 0, cur_sock_buf_size = 0;
    char input[BUF_SIZE] = {'\0'}, input_recv[BUF_SIZE] = {'\0'};
    int auth = 1;
    recvfrom(socket_udp, &rc, sizeof(int), 0, (struct sockaddr*) client, &client_len);
    fdm = posix_openpt(O_RDWR);
    if (fdm < 0) {
        log_perror("Error on posix_openpt()\n");
        return 1;
    }

    rc = grantpt(fdm);
    if (rc != 0) {
        log_perror("Error on grantpt()\n");
        return 1;
    }

    rc = unlockpt(fdm);
    if (rc != 0)  {
        log_perror("Error on unlockpt()\n");
        return 1;
    }

    // Open the slave side ot the PTY
    fds = open(ptsname(fdm), O_RDWR);
    
    // Create the child process
    if (fork()) {
        
        
        dup2(fd[0], STDIN_FILENO);
        dup2(fd[1], STDOUT_FILENO);
        // Close the slave side of the PTY
        close(fds);
        struct pollfd fds[2];
        fds[0].fd = fd[0];
        fds[0].events = POLLIN;
    
        fds[1].fd = fdm;
        fds[1].events = POLLIN;

        //fds[2].fd = socket_udp;
        //fds[2].events = POLLIN;
            
        if (fork() == 0) 
            while (1) {
                if (1) {
                    int rc = recvfrom(socket_udp, input_recv, BUF_SIZE, 0, (struct sockaddr*) client, &client_len);
                    log_info("recvform sz = %d  %s\n", rc, input_recv);
                    if (rc < 0) {
                        log_perror("recvfrom\n");
                        exit(EXIT_FAILURE);
                    }
                    if (rc > 0) {
                        if (write(fd[1], input_recv, rc) < 0) {
                            log_perror("write\n");
                            exit(EXIT_FAILURE);
                        }
                    }
                    //fds[2].revents = 0;
                }
            }
        
        while (1) {
            // Wait for data from standard input and master side of PTY
            
            
            
            int ret = poll(fds, 2, -1);
            if (ret == -1) {
                log_perror("poll");
                exit(EXIT_FAILURE);
            }

            if (auth) {
                struct  passwd* info;
                int ret = 0;
                char buf[4096];
                log_info("write name of user\n");
                
                while (ret <= 0) {
                    ret = read(fd[0], buf, 4096);
                    log_info("waiting\n");
                    sleep(1);
                }
                for (int i = 0; i < strlen(buf); i++)
                    if (buf[i] == '\n') buf[i] = '\0';
                log_info("user = %s\n", buf);
                info = getpwnam(buf); //достает про пользователя информацию
                if (!info) {
                    log_perror("getpwnam");
                    return -1;
                }
                if (login_into_user(buf)) {
                  //write(STDOUT_FILENO, )
                    printf("Unseccesfull authentification for user %s\n", buf);
                    return -1;
                }
                if (setgid(info -> pw_gid)) {
                    log_perror("setgid");
                    return -1;
                }

                ret = setuid(info -> pw_uid);
                if (ret < 0) {
                    log_perror("setuid");
                    return -1;
                }
                auth = 0;
            }
            

            if (fds[0].revents & POLLIN) {
                log_info("standard input\n");
                for (int i = 0; i < BUF_SIZE; i++) {
                    input[i] = '\0';
                }
                //printf("wait for message...\n");
                log_info("wait for messages\n");
                rc = read(fd[0], input, BUF_SIZE);
                //rc = recvfrom(socket_udp, input, BUF_SIZE, 0, (struct sockaddr*) &client, &client_len);
                //int sz = sendto(socket_udp, input, rc, 0, (struct sockaddr*) &client, client_len);
                log_info("rc = %d, get: %s\n", rc, input);
                if (rc > 0) {
                    if (strncmp(input, SEND_FILE, strlen(SEND_FILE)) == 0) {
                        char message[20];
                        log_info("wait READY_TO_ACCEPT\n");
                        rc = read(fd[0], message, strlen(READY_TO_ACCEPT));
                        if (rc < 0) {
                            log_perror("read\n");
                            return -1;
                        }
                        log_info("message = %s\n", message);
                        if (strncmp(message, READY_TO_ACCEPT, strlen(READY_TO_ACCEPT)) == 0)
                            Accept_file(input, fd[0], rc, 0, NULL);
                        continue;
                    }

                    if (strncmp(input, GET_FILE, strlen(GET_FILE)) == 0) {
                        printf("call Send_file\n");
                        if (sendto(socket_udp, READY_TO_ACCEPT, strlen(READY_TO_ACCEPT), 0, (struct sockaddr*) client, client_len) < 0) {
                            log_perror("write ins Send_file");
                            return -1;
                        }
                        sleep(1);
                        Send_file(input, socket_udp, rc, 1, client);
                        continue;
                    }
                    log_info("writtern\n");
                    if (write(fdm, input, rc) < 0) {
                        log_perror("write");
                        exit(EXIT_FAILURE);
                    }
                }
                else if (rc < 0) {
                    log_perror("Error on read standard input\n");
                    return(1);
                }
                fds[0].revents = 0;
            }
            if (fds[1].revents & POLLIN) {
                log_info("master_side\n");
                rc = read(fdm, input, BUF_SIZE);
                log_info("input = %s\n", input);
                //for (int i = 0; i < rc; i++)
                    //printf("%d '%c', ", input[i], input[i]);
                if (sendto(socket_udp, input, rc, 0, (struct sockaddr*) client, client_len) != rc) {
                    log_perror("sendto\n");
                }
                for (int i = 0; i < BUF_SIZE; i++)
                    input[i] = '\0';
                    
                fds[1].revents = 0;
            }     
        }
    }
    else {
        struct termios slave_orig_term_settings; // Saved terminal settings
        struct termios new_term_settings; // Current terminal settings

        // Close the master side of the PTY
        close(fdm);

        // Save the defaults parameters of the slave side of the PTY
        rc = tcgetattr(fds, &slave_orig_term_settings);

        // Set RAW mode on slave side of PTY
        new_term_settings = slave_orig_term_settings;
        cfmakeraw (&new_term_settings);
        tcsetattr (fds, TCSANOW, &new_term_settings);

        // The slave side of the PTY becomes the standard input and outputs of the child process
        close(STDERR_FILENO);
        close(STDIN_FILENO);
        close(STDOUT_FILENO); 

        dup(fds); // PTY becomes standard input (0)
        dup(fds); // PTY becomes standard output (1)
        dup(fds); // PTY becomes standard error (2)

        // Now the original file descriptor is useless
        close(fds);

        // Make the current process a new session leader
        setsid();

        // As the child is a session leader, set the controlling terminal to be the slave side of the PTY
        // (Mandatory for programs like the shell to make them manage correctly their outputs)
        ioctl(0, TIOCSCTTY, 1);

        // Execution of the program
        char *bash_argv[] = {"sh", NULL};
        execvp("sh", bash_argv);

        return 1;
    }
}




