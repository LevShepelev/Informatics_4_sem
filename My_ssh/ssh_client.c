#include "My_ssh.h"

int find_server(struct sockaddr_in* server);
int authentication(struct sockaddr_in* server, char* user_name);
int send_command_udp(struct sockaddr_in* server, int socket_udp);
int write_mess_tcp(mess_t message, int fd, char* buf);
int get_file_udp(struct sockaddr_in* server, int socket_udp);
int send_file_udp(struct sockaddr_in* server, int socket_udp);

#define BUF_SIZE 1000
char buf[BUF_SIZE];

int main(){
    struct sockaddr_in server;
    int is_udp = 0;
    find_server(&server);
    char user_name[BUF_SIZE];
    authentication(&server, user_name);
    
    printf("To use udp press 1, to use tcp press 0\n");
    mess_t connection_type;
    scanf("%d", &is_udp);
    if (is_udp) {
        int socket_udp = socket(AF_INET, SOCK_DGRAM, 0);
        //sendto(socket_udp, &connection_type, sizeof(connection_type), 0, (struct sockaddr*) &server, sizeof(server));
        while(1) {
            int ret = read(STDIN_FILENO, buf, BUF_SIZE);
            COND_ERROR_EXIT(ret, "read");
            if (strncmp(buf, "send", 4))
                    send_file_udp(&server, socket_udp);
            else if (strncmp(buf, "get", 3))
                get_file_udp(&server, socket_udp);
            else if (strncmp(buf, "exit", 4))
                exit(0);
            else send_command_udp(&server, socket_udp);
        }
    }
}

int find_server(struct sockaddr_in* server) {
    int buf_size = 1000;
    struct sockaddr_in client;
    struct in_addr tmp;
    tmp.s_addr = htonl(INADDR_BROADCAST);
    client.sin_family = AF_INET;
    client.sin_port   = htons(27312);
    client.sin_addr   = tmp;
    char* buf = (char*) mycalloc(buf_size, sizeof(char));
    char* buf_receive = (char*) mycalloc(buf_size, sizeof(char));
    sprintf(buf, "%s", "Hello_Buddy\n");
    int socket_udp = socket(AF_INET, SOCK_DGRAM, 0);
    perror("socket\n");
    int a = 1;
    setsockopt(socket_udp, SOL_SOCKET, SO_BROADCAST, &a, sizeof(a));      
    sendto(socket_udp, buf, buf_size, 0, (struct sockaddr*) &client, sizeof(client));

    socklen_t server_len = sizeof(*server);
    recvfrom(socket_udp, buf_receive, buf_size, 0, (struct sockaddr*) server, &server_len);
    printf("get message back %s: %s\n", buf_receive, inet_ntoa((((struct sockaddr_in*) server)->sin_addr)));
    close(socket_udp);
    return 0;
    }

int authentication(struct sockaddr_in* server, char* user_name) {
    int socket_tcp = socket(AF_INET, SOCK_STREAM, 0);
    perror("socket");
    int reuse = 1;
    setsockopt(socket_tcp, SOL_SOCKET, SO_REUSEADDR, (const char *)&reuse, sizeof(int));
    perror("setsocketopt");
    bind(socket_tcp, (struct sockaddr*) server, sizeof(*server));
    connect(socket_tcp, (struct sockaddr*) server, sizeof(*server));
    perror("connect");
    while (1) {
        mess_t message = {AUTH_REQUEST, strlen(user_name)};
        write_mess_tcp(message, socket_tcp, user_name);

        int ret = read(socket_tcp, buf, BUF_SIZE);
        COND_ERROR_EXIT(ret, "read");
        if (((mess_t*) buf) -> mess_type = AUTH_WRONG_USER) {
            log_info("No password request in authentification");
            continue;
        }
        if (((mess_t*) buf) -> mess_type != PASSWORD_REQUEST) {
            log_perror("No password request in authentification");
            exit(1);
        }
        ret = read(STDIN_FILENO, buf, BUF_SIZE);
        COND_ERROR_EXIT(ret, "read");
        message.mess_type = PASSWORD_MESSAGE;
        message.mess_size = strlen(buf);
        write_mess_tcp(message, socket_tcp, buf);
        read(socket_tcp, buf, BUF_SIZE);
        COND_ERROR_EXIT(ret, "read");
        if (((mess_t*) buf) -> mess_type == AUTH_ERROR) {
            log_perror("No password request in authentification");
            exit(1);
        }
        else if (((mess_t*) buf) -> mess_type == AUTH_SUCCESS)
            return 0;
        else if (((mess_t*) buf) -> mess_type == AUTH_WRONG_PASSWORD)
            continue;
        else {
            log_error("Unkown error\n");
            exit(1);
        } 
            
    }
}

int write_mess_tcp(mess_t message, int fd, char* buf) {
    int ret = write(fd, &message, sizeof(message));
    if (ret < 0) 
        log_perror("write");
    ret = write(fd, buf, message.mess_size);
    if (ret < 0) 
        log_perror("write");
    return ret;
}

int write_mess_udp(int socket_udp, mess_t message, char* buf, struct sockaddr_in* server) {
    int ret = sendto(socket_udp, &message, sizeof(message), 0, (struct sockaddr*) server, sizeof(*server));
    if (ret < 0) 
        log_perror("write");
    ret = sendto(socket_udp, buf, message.mess_size, 0, (struct sockaddr*) server, sizeof(*server));
    if (ret < 0) 
        log_perror("write");
    return ret;
}

int send_file_udp(struct sockaddr_in* server, int socket_udp) {
    int ret = read(STDOUT_FILENO, buf, BUF_SIZE);//reading file name
    COND_ERROR_EXIT(ret, "read");

    char path_str[BUF_SIZE] = {0};//reading path where to put file
    ret = read(STDIN_FILENO, path_str, BUF_SIZE);
    COND_ERROR_EXIT(ret, "read");

    int file_fd = open(buf, O_RDONLY);
    if (file_fd < 0) {
        perror("open");
        return -1;
    }
    struct stat statistica;
    int stat_error = stat (buf, &statistica);
    assert(stat_error == 0);

    char* file_buf = (char*) mycalloc(statistica.st_size, sizeof(char));
    ret = read(file_fd, file_buf, statistica.st_size);
    COND_ERROR_EXIT(ret, "read");

    mess_t file = {FILE_BUF, statistica.st_size};
    write_mess_udp(socket_udp, file, file_buf, server);

    mess_t path = {FILE_PATH, strlen(path_str)};
    write_mess_udp(socket_udp, path, path_str, server);

    socklen_t server_len = sizeof(server);
    recvfrom(socket_udp, buf, BUF_SIZE, 0, (struct sockaddr*) &server, &server_len);
    if (((mess_t*) buf) -> mess_type != FILE_SENDING_SUCCESS) {
            log_error("problem with file sending");
            exit(1);
        }
}

int get_file_udp(struct sockaddr_in* server, int socket_udp) {
    int ret = read(STDOUT_FILENO, buf, BUF_SIZE);//reading file name
    COND_ERROR_EXIT(ret, "read");

    char path_str[BUF_SIZE] = {0};//reading path where to put file
    ret = read(STDIN_FILENO, path_str, BUF_SIZE);
    COND_ERROR_EXIT(ret, "read");

    mess_t file = {FILE_REQUEST, strlen(buf)};
    write_mess_udp(socket_udp, file, buf, server);
    socklen_t server_len = sizeof(server);
    recvfrom(socket_udp, buf, BUF_SIZE, 0, (struct sockaddr*) server, &server_len);
    if (((mess_t*) buf) -> mess_type != FILE_SENDING_SUCCESS) {
            log_error("problem with file sending");
            exit(1);
        }

    recvfrom(socket_udp, (char*) &file, sizeof(file), 0, (struct sockaddr*) server, &server_len); 
    if (file.mess_type != FILE_SENDING_SUCCESS){
        log_error("file_sending");
        exit(1);
    }
    char* buf_file = (char*) mycalloc(file.mess_size, sizeof(char));    
    mess_t path;
    recvfrom(socket_udp, (char*) &path, sizeof(path), 0, (struct sockaddr*) server, &server_len);
    if (path.mess_type != PATH_SENDING_SUCCESS){
        log_error("path_sending");
        exit(1);
    }
    char* path_name = (char*) mycalloc(path.mess_size, sizeof(char));
    
    if (recvfrom(socket_udp, buf_file, file.mess_size, 0, (struct sockaddr*) server, &server_len) != file.mess_size)
        perror("recv message");
    if (recvfrom(socket_udp, path_name, path.mess_size, 0, (struct sockaddr*) server, &server_len) != path.mess_size)
        perror("recv path");
    printf("path_name = %s\n", path_name);
    int file_fd = open(path_name, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (file_fd < 0) {
        perror("open");
        return -1;
    }
    if (write(file_fd, buf_file, file.mess_size) != file.mess_size)
        perror("write");
    free(path_name);
    free(buf_file);
}

int send_command_udp(struct sockaddr_in* server, int socket_udp) {
    int sz = read(STDIN_FILENO, buf, sizeof(buf));
    if (sz < 0) {
        perror("read");
        return 1;
    }
    //mess_t command = {COMMAND_REQUEST, strlen(buf)};
    //write_mess_udp(socket_udp, command, buf, server);
    sendto(socket_udp, buf, strlen(buf), server, 0, sizeof(*server));
    //mess_t answer;
    socklen_t server_len = sizeof(server);
    //recvfrom(socket_udp, (char*) &answer, sizeof(answer), 0, (struct sockaddr*) server, &server_len);
    /*if (answer.mess_type != COMMAND_SUCCESS) {
        log_error("COMMAND_RECEIVER");
        exit(1);
    }*/
    char* mybuf = (char*) mycalloc(1000, sizeof(char));
    recvfrom(socket_udp, (char*) mybuf, 1000, 0, (struct sockaddr*) server, &server_len);
    mybuf[strlen(mybuf)] = '\n';
    if (!write(STDOUT_FILENO, mybuf, 1000)) {
        log_error("write");
        exit(1);
    }
}