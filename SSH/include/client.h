#pragma once

extern const char IS_UDP;
extern const char IS_TCP;
extern const char SEARCH;
extern const char NEED_BIND;
extern const char NOT_NEED_BIND;;
extern const char GET_FILE[10];
extern const char SEND_FILE[10];
extern const char EXIT[10];
extern const char TIME_OUT[10];
extern const char READY_TO_ACCEPT[20];
extern const unsigned g;
extern const unsigned p;
extern const uint16_t broadcast_port;
extern const unsigned connection_time; 

int TCP_communication(int broadcast_socket);
int UDP_communication(int broadcast_socket);
int Server_verify_request(int socket, struct sockaddr_in* server);
int Send_symmetric_key(int socket, struct sockaddr_in* server);
int Send_file_sending_message(int socket, char* buf, struct sockaddr_in* server, int sz, int is_udp, int key);
int Broadcast_search(int socket, struct sockaddr_in* server);

const int udp_port = 29435;
const char verify_key[20] = "I am server";
const unsigned searching_servers_time = 10000;