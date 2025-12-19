#ifndef NETWORK_H
#define NETWORK_H

#include <stddef.h>
#include "protocol.h"

// Read exactly total_bytes_to_read or return -1 on error/disconnect
int read_all(int sock, void* buffer, size_t total_bytes_to_read);

// Write exactly total_bytes_to_write or return -1 on error
int write_all(int sock, const void* buffer, size_t total_bytes_to_write);

// Create a TCP connection to ip:port, return socket fd or -1
int tcp_connect(const char* ip, int port);

// Convenience: send a SUCCESS/ERROR response with message
void send_response(int sock, MessageType type, const char* message);

// Get remote peer IP and port for a connected socket. Returns 0 on success.
int get_peer_address(int sock, char* ipbuf, size_t ipbuflen, int* port);

#endif // NETWORK_H
