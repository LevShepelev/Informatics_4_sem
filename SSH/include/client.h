#pragma once

extern const char IS_UDP;
extern const char IS_TCP;
extern const char NEED_BIND;
extern const char NOT_NEED_BIND;;
extern const char GET_FILE[10];
extern const char SEND_FILE[10];
extern const char READY_TO_ACCEPT[20];
extern const uint16_t broadcast_port;

int TCP_communication(int broadcast_socket);
int UDP_communication(int broadcast_socket);
const int udp_port = 29435;