#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include "protocol.h"
#include "network.h"

int read_all(int sock, void* buffer, size_t total_bytes_to_read) {
    size_t bytes_read_so_far = 0;
    char* char_buffer = (char*)buffer;
    while (bytes_read_so_far < total_bytes_to_read) {
        ssize_t bytes = read(sock, char_buffer + bytes_read_so_far, total_bytes_to_read - bytes_read_so_far);
        if (bytes <= 0) {
            return -1;
        }
        bytes_read_so_far += (size_t)bytes;
    }
    return 0;
}

int write_all(int sock, const void* buffer, size_t total_bytes_to_write) {
    size_t bytes_written = 0;
    const char* data = (const char*)buffer;
    while (bytes_written < total_bytes_to_write) {
        ssize_t bytes = write(sock, data + bytes_written, total_bytes_to_write - bytes_written);
        if (bytes <= 0) return -1;
        bytes_written += (size_t)bytes;
    }
    return 0;
}

int tcp_connect(const char* ip, int port) {
    int sock;
    struct sockaddr_in addr;
    sock = socket(PF_INET, SOCK_STREAM, 0);
    if (sock == -1) return -1;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(ip);
    addr.sin_port = htons(port);
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        close(sock);
        return -1;
    }
    return sock;
}

void send_response(int sock, MessageType type, const char* message) {
    PacketHeader res_header;
    ResponsePayload res_payload;
    res_header.type = type;
    res_header.size = sizeof(res_payload);
    // Prefix error messages with numeric error codes for clarity, unless already present.
    if (type == MSG_ERROR) {
        const char* msg = message ? message : "";
        // Detect an existing numeric prefix like "404 "
        int has_prefix = 0;
        if (strlen(msg) >= 4 && isdigit((unsigned char)msg[0]) && isdigit((unsigned char)msg[1]) && isdigit((unsigned char)msg[2]) && msg[3] == ' ') {
            has_prefix = 1;
        }
        if (has_prefix) {
            strncpy(res_payload.message, msg, MAX_MSG_LEN);
        } else {
            int code = 400; // default Bad Request
            // Heuristic mapping based on common substrings
            if (strstr(msg, "not found") || strstr(msg, "Not found") || strstr(msg, "File not found")) code = 404;
            else if (strstr(msg, "Access Denied") || strstr(msg, "Only the owner") || strstr(msg, "do not hold the lock") || strstr(msg, "No lock held")) code = 403;
            else if (strstr(msg, "already exists") || strstr(msg, "already deleted") || strstr(msg, "Race:")) code = 409;
            else if (strstr(msg, "locked")) code = 423;
            else if (strstr(msg, "Internal")) code = 500;
            else if (strstr(msg, "No Storage Servers available") || strstr(msg, "Failed to contact Storage Server") || strstr(msg, "No response from Storage Server")) code = 503;
            // Format as "<code> <message>"
            snprintf(res_payload.message, MAX_MSG_LEN, "%d %s", code, msg);
        }
    } else {
        strncpy(res_payload.message, message ? message : "", MAX_MSG_LEN);
    }
    write_all(sock, &res_header, sizeof(res_header));
    write_all(sock, &res_payload, sizeof(res_payload));
}

int get_peer_address(int sock, char* ipbuf, size_t ipbuflen, int* port) {
    if (!ipbuf || ipbuflen == 0) return -1;
    struct sockaddr_in addr; socklen_t len = sizeof(addr);
    if (getpeername(sock, (struct sockaddr*)&addr, &len) == -1) return -1;
    const char* ip = inet_ntop(AF_INET, &addr.sin_addr, ipbuf, (socklen_t)ipbuflen);
    if (!ip) return -1;
    if (port) *port = ntohs(addr.sin_port);
    return 0;
}
