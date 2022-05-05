#include "../include/lib.h"
#include "../include/server.h"

#define DEBUG
int main() {
    signal(SIGPIPE, SIG_IGN); 

    printf("server_pid = %d\n", getpid());
    
    char buf[BUF_SIZE];
    struct sockaddr_in client;
    int a = 1;
    struct sockaddr_in broadcast_server;
    int socket_broadcast = Socket_config(&broadcast_server, broadcast_port, SOCK_DGRAM, 0, NEED_BIND, htonl(INADDR_ANY));
    if (setsockopt(socket_broadcast, SOL_SOCKET, SO_REUSEADDR, &a, sizeof(a)) < 0) {
        log_perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    while (1){
        socklen_t client_len = sizeof(client);
        int len = recvfrom(socket_broadcast, buf, BUF_SIZE, 0, (struct sockaddr*) &client, &client_len);
        if (len < 0) {
            log_perror("recvfrom");
            return -1;
        }
        if (len == 0) {
            sleep(1);
            continue;
        }

        log_info("Server_verify Msg from: %d\n", ntohs(client.sin_port));
        tcp_port++;
        free_udp_port++;
        if (fork() == 0) {
            Set_child_death_signal();
            if (Create_session(buf[0], socket_broadcast, &client) < 0)
                return -1;
            return 0;
        }
    }        
}
    
    

int TCP_communication(int socket_tcp) {
    log_info("tcp listening...\n");
    struct sockaddr_in client;
    socklen_t client_len = sizeof(client);
    int client_fd = accept(socket_tcp, (struct sockaddr*) &client, &client_len);
    if (client_fd < 0) {
        log_perror("accept\n");
        exit(EXIT_FAILURE);
    }
    Server_verify_answer(client_fd, &client, &client_len);
    int key = Get_symm_key(client_fd, &client, &client_len);
    log_info("Symm_key = %u\n", key);
    if (client_fd < 0) {
        log_perror("accept");
        return 1;
    }
    log_info("accepted\n");
    int fdm = 0, fds = 0;

    if (Terminals_config(&fdm, &fds) < 0)
        return -1;
    int fd_for_dir_name[2];
    if (pipe(fd_for_dir_name) < 0) {
        log_perror("pipe\n");
        exit(EXIT_FAILURE);
    }
    // Create the child process
    if (fork() == 0) {
        Set_child_death_signal();
        // Close the slave side of the PTY
        close(fds);
        if (TCP_terminal_transmitting(client_fd, fdm, fd_for_dir_name[1], key) < 0) {
            log_perror("TCP_terminal_transmitting\n");
            return -1;
        }
    }
    else return Slave_terminal(fds, fdm, fd_for_dir_name[0]);
    return 0;
}


int UDP_communication(int socket_udp, struct sockaddr_in* client) {
    log_info("udp\n");
    int fd[2], fd_out[2];
    if (pipe(fd) < 0) {
        log_perror("pipe\n");
        exit(EXIT_FAILURE);
    }
    if (pipe(fd_out) < 0) {
        log_perror("pipe\n");
        exit(EXIT_FAILURE);
    }
    socklen_t client_len = sizeof(*client); 
    int fdm = 0, fds = 0;
    int rc = 0;
    int fd_for_dir_name[2];
    if (pipe(fd_for_dir_name) < 0) {
        log_perror("pipe\n");
        exit(EXIT_FAILURE);
    }
    char input[BUF_SIZE] = {'\0'}, input_recv[BUF_SIZE] = {'\0'};
    if (recvfrom(socket_udp, &rc, sizeof(int), 0, (struct sockaddr*) client, &client_len) < 0) {
        log_perror("recvfrom\n");
        exit(EXIT_FAILURE);
    }
    Server_verify_answer(socket_udp, client, &client_len);
    int key = Get_symm_key(socket_udp, client, &client_len);
    log_info("Symm_key = %u", key);

    if (Terminals_config(&fdm, &fds) < 0)
        return -1;
    // Create the child process
    if (fork() == 0) {
        Set_child_death_signal();
        if (dup2(fd[0], STDIN_FILENO) < 0) {
            log_perror("dup\n");
            exit(EXIT_FAILURE);
        }
        if (dup2(fd_out[1], STDOUT_FILENO) < 0) {
            log_perror("dup\n");
            exit(EXIT_FAILURE);
        }
        // Close the slave side of the PTY
        close(fds);

        struct pollfd fd_in[2];
        fd_in[0].fd = fd[0];
        fd_in[0].events = POLLIN;
    
        fd_in[1].fd = fdm;
        fd_in[1].events = POLLIN;
            
        if (fork() == 0) {
            Set_child_death_signal();
            struct pollfd fd_socket = {socket_udp, POLLIN, 0};
            while (1) {
                int ret = poll(&fd_socket, 1, connection_time);
                if (ret == -1) {
                    log_perror("poll");
                    exit(EXIT_FAILURE);
                }
                if (ret == 0) {
                    log_info("client reader finished\n");
                    return 0;
                } 
                int rc = Recvfrom_safe(socket_udp, input_recv, BUF_SIZE, 0, (struct sockaddr*) client, &client_len, key);
                log_info("server receive sz = %d  %s\n", rc, input_recv);
                if (rc < 0) {
                    log_perror("recvfrom\n");
                    exit(EXIT_FAILURE);
                }
                
                if (rc > 0) {
                    if (write(fd[1], input_recv, rc) < 0) {
                        log_perror("write\n");
                        exit(EXIT_FAILURE);
                    }
                    if (strncmp(input_recv, SEND_FILE, strlen(SEND_FILE)) == 0) {
                        log_info("sleep_send_file\n");
                        sleep(1);
                    }
                }
            }
        }
        if (fork() == 0) {
            Set_child_death_signal();
            struct pollfd fd_pipe = {fd_out[0], POLLIN, 0};
            while(1) {
                int ret = poll(&fd_pipe, 1, connection_time);
                if (ret == -1) {
                    log_perror("poll");
                    exit(EXIT_FAILURE);
                }
                if (ret == 0) {
                    log_info("pipe reader finished\n");
                    return 0;
                } 
                rc = read(fd_out[0], input, BUF_SIZE);
                log_info("server sends = %s\n", input);
                //for (int i = 0; i < rc; i++)
                    //printf("%d '%c', ", input[i], input[i]);
                if (Sendto_safe(socket_udp, input, rc, 0, (struct sockaddr*) client, client_len, key) != rc) {
                    log_perror("sendto\n");
                }
                memset(input, '\0', BUF_SIZE);                    
            }
        }     
            
        if (UDP_terminal_transmitting(fd_in, fdm, fd, fd_out, input, socket_udp, client, client_len, fd_for_dir_name[1], key) < 0) {
            log_error("transmitting_ended\n");
            return -1;
        }
    }
    else return Slave_terminal(fds, fdm, fd_for_dir_name[0]);
    log_info("transmitiing finished\n");
    return 0;
}


int Login_into_user(char* username){
    pam_handle_t* pam;
    int ret;

    ret = pam_start("myssh", username, &my_conv, &pam);
    if (ret != PAM_SUCCESS){
        printf("Failed pam_start");
        return -1;
    }

    ret = pam_authenticate(pam, PAM_SILENT);
    if (ret != PAM_SUCCESS) {
        printf("Incorrect password!\n");
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


int Authetification(int fd_in, int fd_out, int fdm, int is_udp, int key, int using_socket) {
    struct  passwd* info;
    int ret = 0;
    char buf[BUF_SIZE] = {'\0'};
    log_info("write name of user\n");
    int fork_code = 0;
    if (!is_udp) {
        int fd[2], fd_out[2];
        if (pipe(fd) < 0) {
            log_perror("pipe\n");
            exit(EXIT_FAILURE);
        }

        if (pipe(fd_out) < 0) {
            log_perror("pipe\n");
            exit(EXIT_FAILURE);
        }

        int fd_for_dir_name[2];
        if (pipe(fd_for_dir_name) < 0) {
            log_perror("pipe\n");
            exit(EXIT_FAILURE);
        }

        Set_child_death_signal();
        if (dup2(fd[0], STDIN_FILENO) < 0) {
            log_perror("dup\n");
            exit(EXIT_FAILURE);
        }

        if (dup2(fd_out[1], STDOUT_FILENO) < 0) {
            log_perror("dup\n");
            exit(EXIT_FAILURE);
        }

        fork_code = fork();
        if (fork_code == 0) 
            Pipe_for_auth(using_socket, key, fd_out[0], fd[1]);
    }
    if (is_udp)
        printf_fd(fd_out, "login: ");
    else 
        printf_fd_safe(fd_out, key, "login: ");

    while (ret <= 0) {
        ret = read(fd_in, buf, KEY_MAX_SIZE);
        log_info("waiting\n");
        sleep(1);
    }

    for (int i = 0; i < strlen(buf); i++)
        if (buf[i] == '\n') 
            buf[i] = '\0';
    log_info("authetification: user = %s\n", buf);
    info = getpwnam(buf); //достает про пользователя информацию
    if (!info) {
        if (is_udp)
            printf_fd(fd_out, "Wrong name of user, try again\n");
        else 
            printf_fd_safe(fd_out, key, "Wrong name of user, try again\n");
        log_perror("getpwnam");
        return -1;
    }
    if (is_udp)
        printf_fd(fd_out, "password: ");
    else 
        printf_fd_safe(fd_out, key, "password: ");

    if (Login_into_user(buf)) {
        if (is_udp)
            printf_fd(fd_out, "Unseccesfull authentification\n");
        else 
            printf_fd_safe(fd_out, key, "Unseccesfull authentification\n");
        return -1;
    }
    if (!is_udp) {
        if (kill(fork_code, SIGINT) < 0) {
            log_perror("kill\n");
            exit(EXIT_FAILURE);
        }
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
    char dir_name[BUF_SIZE] = {'\0'};
    memcpy(dir_name, "/home/", strlen("/home/"));
    if (chdir(strcat(dir_name, buf)) < 0) {
        log_perror("chdir\n");
        exit(EXIT_FAILURE);
    }
            log_info("auth ended\n");
    if (write(fdm, dir_name, strlen(dir_name)) < 0) {
        log_perror("write\n");
        exit(EXIT_FAILURE);
    }
    return 0;
}


int Slave_terminal(int fds, int fdm, int fd_for_dir_name) {
    
    struct termios slave_orig_term_settings; // Saved terminal settings
    struct termios new_term_settings; // Current terminal settings
    char dir_name[BUF_SIZE] = {'\0'};
    int ret = read(fd_for_dir_name, dir_name, BUF_SIZE);
    if (ret <= 0) {
        log_perror("slave didnt get new direcroty name\n");
        exit(EXIT_FAILURE);
    }
    log_info("slave has change directory %s\n", dir_name);
    if (chdir(dir_name) < 0) {
        log_perror("chdir\n");
        exit(EXIT_FAILURE);
    }
    // Close the master side of the PTY
    close(fdm);
    // Save the defaults parameters of the slave side of the PTY
    tcgetattr(fds, &slave_orig_term_settings);

    // Set RAW mode on slave side of PTY
    new_term_settings = slave_orig_term_settings;
    cfmakeraw (&new_term_settings);
    tcsetattr (fds, TCSANOW, &new_term_settings);

    // The slave side of the PTY becomes the standard input and outputs of the child process
    close(STDERR_FILENO);
    close(STDIN_FILENO);
    close(STDOUT_FILENO); 

    if (dup(fds) < 0 || dup(fds) < 0 || dup(fds) < 0) {
        log_perror("dup\n");
        exit(EXIT_FAILURE);
    }
   
    // Now the original file descriptor is useless
    close(fds);

    // Make the current process a new session leader
    if (setsid() < 0) {
        log_perror("setsid\n");
        exit(EXIT_FAILURE);
    }

    // As the child is a session leader, set the controlling terminal to be the slave side of the PTY
    // (Mandatory for programs like the shell to make them manage correctly their outputs)
    if (ioctl(0, TIOCSCTTY, 1) < 0) {
        log_perror("ioctl\n");
        exit(EXIT_FAILURE);
    }

    // Execution of the program
    char *bash_argv[] = {"sh", NULL};
    if (execvp("sh", bash_argv) < 0) {
        log_perror("execvp\n");
        exit(EXIT_FAILURE);
    }
    return 1;
}


int UDP_terminal_transmitting(struct pollfd fd_in[3], int fdm, int fd[2], int fd_out[2], char* input, int socket_udp, struct sockaddr_in* client, socklen_t client_len, int fd_for_dir_name, int key) {
    int auth = 1;
    while (auth) {
        auth = Authetification(fd[0], fd_out[1], fd_for_dir_name, 1, key, socket_udp);
    }

    while (1) {
        int ret = poll(fd_in, 2, connection_time);
        if (ret == -1) {
            log_perror("poll");
            exit(EXIT_FAILURE);
        }
        if (ret == 0) {
            if (Sendto_safe(socket_udp, TIME_OUT, strlen(TIME_OUT), 0, (struct sockaddr*) client, client_len, key) != strlen(TIME_OUT))
                log_perror("sendto\n");
            return 0;
        } 

        if (fd_in[0].revents & POLLIN) {
            memset(input, '\0', BUF_SIZE);
            log_info("wait for messages\n");
            int rc = read(fd_in[0].fd, input, BUF_SIZE);
            log_info("rc = %d, get: %s\n", rc, input);

            if (rc < 0) {
                log_perror("Error on read standard input\n");
                return(1);
            }
            if (Check_message_send_file(input, socket_udp, 1, (struct sockaddr_in*) client, key) == 1) {
                    Sendto_safe(socket_udp, "File was accepted\n", strlen("File was accepted\n"), 0, client, client_len, key);
                    write(fdm, "\n", strlen("\n"));
                    continue;
                }

            if (strncmp(input, EXIT, strlen(EXIT)) == 0) {
                log_info("client disconected\n");
                return 0;
            }
            if (strncmp(input, GET_FILE, strlen(GET_FILE)) == 0) {
                printf("call Send_file\n");
                if (Sendto_safe(socket_udp, READY_TO_ACCEPT, strlen(READY_TO_ACCEPT), 0, (struct sockaddr*) client, client_len, key) < 0) {
                    log_perror("write ins Send_file");
                    return -1;
                }
                sleep(1);
                Send_file(input, socket_udp, rc, 1, client, key);
                continue;
            }
            log_info("written, %s\n", input);
            if (write(fdm, input, rc) < 0) {
                log_perror("write");
                exit(EXIT_FAILURE);
            }

            fd_in[0].revents = 0;
        }

        if (fd_in[1].revents & POLLIN) {
            log_info("master_side\n");
            int rc = read(fd_in[1].fd, input, BUF_SIZE);
            log_info("input = %s\n", input);
            //for (int i = 0; i < rc; i++)
                //printf("%d '%c', ", input[i], input[i]);
            if (Sendto_safe(socket_udp, input, rc, 0, (struct sockaddr*) client, client_len, key) != rc) {
                log_perror("sendto\n");
            }
            memset(input, '\0', BUF_SIZE);
                
            fd_in[1].revents = 0;
        }     
    }
}


int TCP_terminal_transmitting(int client_fd, int fdm, int fd_for_dir_name, int key) {
    struct pollfd fds[2];
    fds[0].fd = client_fd;
    fds[0].events = POLLIN;
    
    fds[1].fd = fdm;
    fds[1].events = POLLIN;

    int auth = 1;
    char input[BUF_SIZE] = {'\0'};
    while (auth) {
        auth = Authetification(STDIN_FILENO, STDOUT_FILENO, fd_for_dir_name, 0, key, client_fd);
        char bufer[BUF_SIZE] = {'\0'};
        log_info("from fdm %s\n", bufer);
    }

    if (dup2(client_fd, STDIN_FILENO) < 0) {
        log_perror("dup\n");
        exit(EXIT_FAILURE);
    }   

    if (dup2(client_fd, STDOUT_FILENO) < 0) {
        log_perror("dup\n");
        exit(EXIT_FAILURE);
    }

    while (1) {
        int ret = poll(fds, 2, connection_time);
        if (ret == -1) {
            log_perror("poll");
            exit(EXIT_FAILURE);
        }

        if (ret == 0) {
            log_info("Timeout nobody sends messages\n");
            if (Write_safe(client_fd, TIME_OUT, strlen(TIME_OUT), key) != strlen(TIME_OUT))
                log_perror("sendto\n");
            return 0;
        }
        
        if (fds[0].revents & POLLIN)  {
            fds[0].revents = 0;
            int rc = Read_safe(client_fd, input, BUF_SIZE, key);
            log_info("standard input was red %d symbols\n", rc);
            if (rc == 0)
                return 0;
            if (rc < 0) {
                log_perror("Error on read standard input\n");
                return(1);
            }

            if (Check_message_send_file(input, client_fd, 0, NULL, key) == 1) {
                Write_safe(client_fd, "File was accepted\n", strlen("File was accepted\n"), key);
                write(fdm, "\n", strlen("\n"));
                continue;
            }

            if (strncmp(input, EXIT, strlen(EXIT) == 0)) {
                log_info("client disconected\n");
                return 0;
            }

            if (strncmp(input, GET_FILE, strlen(GET_FILE)) == 0) {
                printf("call Send_file\n");
                if (write(client_fd, READY_TO_ACCEPT, strlen(READY_TO_ACCEPT)) < 0) {
                    log_perror("write ins Send_file");
                    return -1;
                }
                sleep(1);
                Send_file(input, client_fd, rc, 0, 0, key);
                continue;
            }

            write(fdm, input, rc);
        }

        if (fds[1].revents & POLLIN) {
            fds[1].revents = 0;
            log_info("master_side\n");
            int rc = read(fdm, input, BUF_SIZE);
            Write_safe(client_fd, input, rc, key);
        }     
    }
}


int Server_verify_answer(int socket, struct sockaddr_in* client, socklen_t* client_len) {
    char buf[BUF_SIZE] = {'\0'}, *message = NULL;
    int ret = recvfrom(socket, buf, BUF_SIZE, 0, (struct sockaddr*) client, client_len);
    if (ret < 0) {
        log_perror("recvfrom\n");
        exit(EXIT_FAILURE);
    }
    
    FILE* privKey_file = fopen("/home/lev/Informatics_4_sem/SSH/src/server_keys/private.key", "rb");
    if (privKey_file == NULL) {
        log_perror("fopen error\n");
        exit(EXIT_FAILURE);
    }
    int mess_size = Decrypt(buf, ret, &message, privKey_file);
    fclose(privKey_file);

    log_info("socket = %d, message = %s\n mess_size = %d\n", socket, message, mess_size);
    if (sendto(socket, message, mess_size, 0, (struct sockaddr*) client, *client_len) < 0) {
        log_perror("sendto\n");
        exit(EXIT_FAILURE);
    }
    free(message);
    return 0;
}

int Get_symm_key(int socket, struct sockaddr_in* client, socklen_t* client_len) {
    char buf[KEY_MAX_SIZE] = {'\0'}, *message = NULL;
    int b = rand() % 10;
    int A = 0, B = (int) powl(g, b) % p;
    int ret = recvfrom(socket, buf, KEY_MAX_SIZE, 0, (struct sockaddr*) client, client_len);
    if (ret < 0) {
        log_perror("recvfrom\n");
        exit(EXIT_FAILURE);
    }
    FILE* privKey_file = fopen("/home/lev/Informatics_4_sem/SSH/src/server_keys/private.key", "rb");
    int mess_size = Decrypt(buf, ret, &message, privKey_file);
    if (mess_size == sizeof(int))
        memcpy(&A, message, mess_size);
    else {
        log_error("wrong size of message with A (part of symmetric key)\n");
        exit(EXIT_FAILURE);
    }
    ret = recvfrom(socket, buf, KEY_MAX_SIZE, 0, (struct sockaddr*) client, client_len);
    if (ret < 0) {
        log_perror("recvfrom\n");
        exit(EXIT_FAILURE);
    }
    FILE* client_pub_key = fopen("/home/lev/Informatics_4_sem/SSH/src/server_keys/client_pub.key", "wb");
    ret = fwrite(buf, sizeof(char), ret, client_pub_key);
    if (ret < 0) {
        log_perror("fwrite failed\n");
        exit(EXIT_FAILURE);
    }
    fclose(client_pub_key);
    client_pub_key = fopen("/home/lev/Informatics_4_sem/SSH/src/server_keys/client_pub.key", "rb");
    mess_size = Encrypt((char*) &B, sizeof(int), &message, client_pub_key);
    if (mess_size == -1) {
        log_perror("encrypt A error\n");
        exit(EXIT_FAILURE);
    }
    ret = sendto(socket, message, mess_size, 0, (struct sockaddr*) client, sizeof(*client));
    if (ret != mess_size) {
        log_perror("send\n");
        exit(EXIT_FAILURE);
    }
    return ((int) powl(A, b)) % p;
}


int Create_session(char is_udp, int socket_broadcast, struct sockaddr_in* client) {
    if (is_udp == IS_UDP) {
        int socket_udp = 0;
        struct sockaddr_in server;
        do {
            socket_udp = Socket_config(&server, free_udp_port, SOCK_DGRAM, SO_REUSEADDR, NEED_BIND, htonl(INADDR_ANY));//TODO:fix port
        } while (socket_udp <= 0);
        if (sendto(socket_broadcast, &free_udp_port, sizeof(free_udp_port), 0, (struct sockaddr*) client, sizeof(*client)) < 0) {
            log_perror("sendto");
            exit(EXIT_FAILURE);
        }

        if (free_udp_port - udp_port_first > MAX_CLIENTS) {
            log_error("too much udp clients\n");
            return -2;
        }
        
        UDP_communication(socket_udp, client);
        close(socket_udp);
    }

    else if (is_udp == IS_TCP) {
        struct sockaddr_in tcp_server;
        log_info("tcp_port = %d\n", tcp_port);
        int socket_tcp = Socket_config(&tcp_server, tcp_port, SOCK_STREAM, SO_REUSEADDR, NEED_BIND, htonl(INADDR_ANY));
        if (listen(socket_tcp, MAX_CLIENTS) < 0) {
            log_perror("listen");
            return 1;
        }
        sendto(socket_broadcast, &tcp_port, sizeof(tcp_port), 0, (struct sockaddr*) client, sizeof(*client));
        log_info("port_sended\n");
        TCP_communication(socket_tcp);
        close(socket_tcp);
    }

    else if (is_udp == SEARCH) {
        sendto(socket_broadcast, &tcp_port, sizeof(tcp_port), 0, (struct sockaddr*) client, sizeof(*client));
    }
    return 0;
}


int Terminals_config(int* fdm, int* fds) {
    *fdm = posix_openpt(O_RDWR);
    if (*fdm < 0) {
        log_perror("Error on posix_openpt()\n");
        return -1;
    }

    int rc = grantpt(*fdm);
    if (rc != 0) {
        log_perror("Error on grantpt()\n");
        return -1;
    }

    rc = unlockpt(*fdm);
    if (rc != 0)  {
        log_perror("Error on unlockpt()\n");
        return -1;
    }

    // Open the slave side ot the PTY
    *fds = open(ptsname(*fdm), O_RDWR);
    return 0;
}


int Check_message_send_file(char* input, int socket, int is_udp, struct sockaddr_in* client, int key) {
    if (strncmp(input, SEND_FILE, strlen(SEND_FILE)) == 0) {
        char message[sizeof(READY_TO_ACCEPT)];
        socklen_t client_len = sizeof(*client);
        int rc = 0;
        log_info("wait READY_TO_ACCEPT\n");
        if (is_udp) 
            rc = Recvfrom_safe(socket, message, strlen(READY_TO_ACCEPT), 0, client, &client_len, key);
        else rc = Read_safe(socket, message, strlen(READY_TO_ACCEPT), key);
        if (rc < 0) {
            log_perror("read\n");
            return -1;
        }
        log_info("message = %s\n", message);
        if (strncmp(message, READY_TO_ACCEPT, strlen(READY_TO_ACCEPT)) == 0)
            Accept_file(input, socket, rc, is_udp, NULL, key);
        log_info("file_accepted\n");
        return 1;
    }
    return 0;
}


int Pipe_for_auth(int socket_tcp, int key, int fd_out, int fd) {
    char input[BUF_SIZE] = {'\0'}, input_recv[BUF_SIZE] = {'\0'};
    int rc = 0;
    struct pollfd fd_socket[2] = {{socket_tcp, POLLIN, 0}, {fd_out, POLLIN, 0}};
    while (1) {
        int ret = poll(fd_socket, 2, connection_time);
        if (ret == -1) {
            log_perror("poll");
            exit(EXIT_FAILURE);
        }
        if (ret == 0) {
            log_info("client reader finished\n");
            return 0;
        } 
        if (fd_socket[0].revents & POLL_IN) {
            int rc = Read_safe(socket_tcp, input_recv, BUF_SIZE, key);
            log_info("recvform sz = %d  %s\n", rc, input_recv);
            if (rc < 0) {
                log_perror("recvfrom\n");
                exit(EXIT_FAILURE);
            }
            if (rc == 0)
                sleep(1);
            if (rc > 0) {
                if (write(fd, input_recv, rc) < 0) {
                    log_perror("write\n");
                    exit(EXIT_FAILURE);
                }
            fd_socket[0].revents = 0;
        }
        
        }
        if (fd_socket[1].revents & POLL_IN) {
            log_info("master_side\n");
            rc = Read_safe(fd_out, input, BUF_SIZE, key);
            if (rc == 0)
                sleep(1);
            log_info("input = %s\n", input);
            //for (int i = 0; i < rc; i++)
                //printf("%d '%c', ", input[i], input[i]);
            if (Write_safe(socket_tcp, input, rc, key) != rc) {
                log_perror("sendto\n");
            }
            memset(input, '\0', BUF_SIZE);     
        fd_socket[1].revents = 0;               
        }
    }        
}