#pragma once

extern const char IS_UDP;
extern const char IS_TCP;
extern const char NEED_BIND;
extern const char NOT_NEED_BIND;;
extern const char GET_FILE[10];
extern const char SEND_FILE[10];
extern const char READY_TO_ACCEPT[20];
extern const uint16_t broadcast_port;

int TCP_communication(int socket_tcp);
int UDP_communication(int socket_udp, struct sockaddr_in* client);
int Login_into_user(char* username);
int Authetification(int fd_in, int fd_out);
int UDP_terminal_transmitting(struct pollfd fd_in[3], int fdm, int fd[2], int fd_out[2], char* input, int socket_udp, struct sockaddr_in* client, socklen_t client_len);
int Slave_terminal(int fds, int fdm);
int TCP_terminal_transmitting(int client_fd, int fdm);
int Server_verify_answer(int socket, struct sockaddr_in* client, socklen_t* client_len);

const uint16_t tcp_port = 30041;
const uint16_t udp_port_first = 25001;
const unsigned connection_time = 10000; //~30 min we wait between messages before shutdowning connection with client

#define MAX_CLIENTS 100

struct pam_conv my_conv = {
    misc_conv,
    NULL,
};
