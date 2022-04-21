#pragma once

extern const char IS_UDP;
extern const char IS_TCP;
extern const char SEARCH;
extern const char NEED_BIND;
extern const char NOT_NEED_BIND;
extern const char GET_FILE[10];
extern const char SEND_FILE[10];
extern const char EXIT[10];
extern const char TIME_OUT[10];
extern const char READY_TO_ACCEPT[20];
extern const unsigned g;
extern const unsigned p;
extern const uint16_t broadcast_port;
extern const unsigned connection_time; 

int TCP_communication(int socket_tcp);
int UDP_communication(int socket_udp, struct sockaddr_in* client);
int Login_into_user(char* username);
int Authetification(int fd_in, int fd_out, int fdm, int is_udp, int key);
int UDP_terminal_transmitting(struct pollfd fd_in[3], int fdm, int fd[2], int fd_out[2], char* input, int socket_udp, struct sockaddr_in* client, socklen_t client_len,  int fd_for_dir_name, int key);
int Slave_terminal(int fds, int fdm, int fd_for_dir_name);
int TCP_terminal_transmitting(int client_fd, int fdm, int fd_for_dir_name, int key);
int Server_verify_answer(int socket, struct sockaddr_in* client, socklen_t* client_len);
unsigned Get_symm_key(int socket, struct sockaddr_in* client, socklen_t* client_len);
int Create_session(char is_udp, int socket_broadcast, struct sockaddr_in* client);
int Terminals_config(int* fdm, int* fds);
int Check_message_send_file(char* input, int socket, int is_udp, struct sockaddr_in* client, int key);

const uint16_t udp_port_first = 25005;
const uint16_t tcp_port_first = 30001;
uint16_t free_udp_port = udp_port_first;
uint16_t tcp_port = tcp_port_first;


#define MAX_CLIENTS 100

struct pam_conv my_conv = {
    misc_conv,
    NULL,
};
