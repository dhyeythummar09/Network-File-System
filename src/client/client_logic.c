#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include "client_logic.h"
#include "../common/network.h"

// Globals declared extern in header, defined in client_main.c
extern char username[MAX_USERNAME_LEN];
extern char nm_ip[16];
extern int nm_port;

// Helper: connect to arbitrary server
int connect_to_server(const char* ip, int port) {
    int sock;
    struct sockaddr_in addr;
    sock = socket(PF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
        perror("socket");
        return -1;
    }
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(ip);
    addr.sin_port = htons(port);
    if (connect(sock, (struct sockaddr*) &addr, sizeof(addr)) == -1) {
        perror("connect");
        close(sock);
        return -1;
    }
    return sock;
}

int wait_for_response_get_status(int sock) {
    PacketHeader h;
    ResponsePayload r;
    if (read(sock, &h, sizeof(h)) <= 0) return 0;
    if (read(sock, &r, h.size) <= 0) return 0;
    if (h.type == MSG_SUCCESS) {
        printf("SERVER: %s\n", r.message);
        return 1;
    } else {
        printf("SERVER ERROR: %s\n", r.message);
        return 0;
    }
}

void wait_for_response(int sock) {
    (void) wait_for_response_get_status(sock);
}

int iequals(const char* a, const char* b) {
    for (; *a && *b; ++a, ++b) {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) return 0;
    }
    return *a == '\0' && *b == '\0';
}

// --- Registration ---
void register_with_nm() {
    int sock = connect_to_server(nm_ip, nm_port);
    if (sock == -1) {
        printf("Could not connect to Name Server. Exiting.\n");
        exit(1);
    }
    PacketHeader h;
    h.type = MSG_CLIENT_REGISTER;
    h.size = sizeof(ClientRegisterPayload);
    ClientRegisterPayload p;
    memset(&p, 0, sizeof(p));
    strncpy(p.username, username, MAX_USERNAME_LEN);
    strncpy(p.ip_addr, "127.0.0.1", sizeof(p.ip_addr));
    p.nm_port = nm_port;
    p.ss_port = 0;
    write(sock, &h, sizeof(h));
    write(sock, &p, sizeof(p));
    wait_for_response(sock);
    close(sock);
}

// --- File Operations ---
void handle_create(const char* filename) {
    int nm_sock = connect_to_server(nm_ip, nm_port);
    if (nm_sock == -1) return;
    PacketHeader h;
    FileRequestPayload p;
    h.type = MSG_CREATE_FILE;
    h.size = sizeof(p);
    memset(&p, 0, sizeof(p));
    strncpy(p.filename, filename, MAX_PATH_LEN);
    strncpy(p.username, username, MAX_USERNAME_LEN);
    write(nm_sock, &h, sizeof(h));
    write(nm_sock, &p, sizeof(p));
    wait_for_response(nm_sock);
    close(nm_sock);
}

void handle_read(const char* filename) {
    int nm_sock = connect_to_server(nm_ip, nm_port);
    if (nm_sock == -1) return;
    PacketHeader req_h;
    FileRequestPayload req_p;
    req_h.type = MSG_READ_FILE;
    req_h.size = sizeof(req_p);
    memset(&req_p, 0, sizeof(req_p));
    strncpy(req_p.filename, filename, MAX_PATH_LEN);
    strncpy(req_p.username, username, MAX_USERNAME_LEN);
    write(nm_sock, &req_h, sizeof(req_h));
    write(nm_sock, &req_p, sizeof(req_p));
    PacketHeader res_h;
    if (read(nm_sock, &res_h, sizeof(res_h)) <= 0) {
        close(nm_sock);
        return;
    }
    if (res_h.type == MSG_ERROR) {
        ResponsePayload err;
        read(nm_sock, &err, res_h.size);
        printf("SERVER ERROR: %s\n", err.message);
        close(nm_sock);
        return;
    }
    SSRedirectPayload red;
    read(nm_sock, &red, res_h.size);
    close(nm_sock);
    printf("Connecting to Storage Server at %s:%d...\n", red.ip_addr, red.port);
    int ss = connect_to_server(red.ip_addr, red.port);
    if (ss == -1) return;
    req_h.type = MSG_SS_READ_FILE;
    req_h.size = sizeof(req_p);
    write(ss, &req_h, sizeof(req_h));
    write(ss, &req_p, sizeof(req_p));
    SSReadPayload fc;
    memset(&fc, 0, sizeof(fc));
    read(ss, &res_h, sizeof(res_h));
    read(ss, &fc, res_h.size);
    if (res_h.type == MSG_SUCCESS)
        printf("--- File Content ---\n%s\n--------------------\n", fc.content);
    else
        printf("STORAGE SERVER ERROR: Failed to read file.\n");
    close(ss);
}

void handle_write(const char* filename, const char* content) {
    int nm_sock = connect_to_server(nm_ip, nm_port);
    if (nm_sock == -1) return;
    PacketHeader req_h;
    FileRequestPayload req_p;
    req_h.type = MSG_WRITE_FILE;
    req_h.size = sizeof(req_p);
    memset(&req_p, 0, sizeof(req_p));
    strncpy(req_p.filename, filename, MAX_PATH_LEN);
    strncpy(req_p.username, username, MAX_USERNAME_LEN);
    write(nm_sock, &req_h, sizeof(req_h));
    write(nm_sock, &req_p, sizeof(req_p));
    PacketHeader res_h;
    read(nm_sock, &res_h, sizeof(res_h));
    if (res_h.type == MSG_ERROR) {
        ResponsePayload err;
        read(nm_sock, &err, res_h.size);
        printf("SERVER ERROR: %s\n", err.message);
        close(nm_sock);
        return;
    }
    SSRedirectPayload red;
    read(nm_sock, &red, res_h.size);
    close(nm_sock);
    printf("Connecting to Storage Server at %s:%d...\n", red.ip_addr, red.port);
    int ss = connect_to_server(red.ip_addr, red.port);
    if (ss == -1) return;
    req_h.type = MSG_SS_WRITE_FILE;
    req_h.size = sizeof(SSWritePayload);
    SSWritePayload w;
    memset(&w, 0, sizeof(w));
    strncpy(w.filename, filename, MAX_PATH_LEN);
    strncpy(w.content, content, MAX_MSG_LEN);
    write(ss, &req_h, sizeof(req_h));
    write(ss, &w, sizeof(w));
    wait_for_response(ss);
    close(ss);
}

extern void handle_write_sentence(const char* filename, int sentence_number); // implemented below

static int ss_send_sentence_update(const SSRedirectPayload* r, const SSWriteSentencePayload* w) {
    int ss = connect_to_server(r->ip_addr, r->port);
    if (ss == -1) return -1;
    PacketHeader h;
    h.type = MSG_SS_WRITE_SENTENCE;
    h.size = sizeof(*w);
    write(ss, &h, sizeof(h));
    write(ss, w, sizeof(*w));
    int ok = wait_for_response_get_status(ss);
    close(ss);
    return ok ? 0 : -1;
}

static int ss_send_etirw(const SSRedirectPayload* r, const SimpleFileUserSentencePayload* p) {
    int ss = connect_to_server(r->ip_addr, r->port);
    if (ss == -1) return -1;
    PacketHeader h;
    h.type = MSG_SS_ETIRW;
    h.size = sizeof(*p);
    write(ss, &h, sizeof(h));
    write(ss, p, sizeof(*p));
    int ok = wait_for_response_get_status(ss);
    close(ss);
    return ok ? 0 : -1;
}

void handle_write_sentence(const char* filename, int sentence_number) {
    int nm_sock = connect_to_server(nm_ip, nm_port);
    if (nm_sock == -1) return;
    PacketHeader req_h;
    FileRequestPayload req_p;
    req_h.type = MSG_WRITE_FILE;
    req_h.size = sizeof(req_p);
    memset(&req_p, 0, sizeof(req_p));
    strncpy(req_p.filename, filename, MAX_PATH_LEN);
    strncpy(req_p.username, username, MAX_USERNAME_LEN);
    write(nm_sock, &req_h, sizeof(req_h));
    write(nm_sock, &req_p, sizeof(req_p));
    PacketHeader res_h;
    if (read(nm_sock, &res_h, sizeof(res_h)) <= 0) {
        close(nm_sock);
        return;
    }
    if (res_h.type == MSG_ERROR) {
        ResponsePayload err;
        read(nm_sock, &err, res_h.size);
        printf("SERVER ERROR: %s\n", err.message);
        close(nm_sock);
        return;
    }
    SSRedirectPayload red;
    read(nm_sock, &red, res_h.size);
    close(nm_sock);
    int session_id = (int) getpid() ^ (int) time(NULL);
    SSWriteSentencePayload w;
    memset(&w, 0, sizeof(w));
    strncpy(w.username, username, MAX_USERNAME_LEN);
    strncpy(w.filename, filename, MAX_PATH_LEN);
    w.sentence_number = sentence_number;
    w.word_index = -1;
    w.session_id = session_id;
    printf("Connecting to Storage Server at %s:%d...\n", red.ip_addr, red.port);
    if (ss_send_sentence_update(&red, &w) != 0) return;
    printf("Sentence locked. Enter '<word_index> <content>' lines, then 'ETIRW' to finish.\n");
    char line[MAX_MSG_LEN];
    while (1) {
        printf("edit> ");
        if (!fgets(line, sizeof(line), stdin)) break;
        line[strcspn(line, "\n")] = 0;
        if (iequals(line, "ETIRW")) {
            SimpleFileUserSentencePayload e;
            memset(&e, 0, sizeof(e));
            strncpy(e.username, username, MAX_USERNAME_LEN);
            strncpy(e.filename, filename, MAX_PATH_LEN);
            e.sentence_number = sentence_number;
            e.session_id = session_id;
            ss_send_etirw(&red, &e);
            break;
        }
        char* tok = strtok(line, " ");
        if (!tok) continue;
        int widx = atoi(tok);
        char* content = strtok(NULL, "");
        if (!content) {
            printf("Usage: <word_index> <content>\n");
            continue;
        }
        SSWriteSentencePayload up;
        memset(&up, 0, sizeof(up));
        strncpy(up.username, username, MAX_USERNAME_LEN);
        strncpy(up.filename, filename, MAX_PATH_LEN);
        up.sentence_number = sentence_number;
        up.word_index = widx;
        strncpy(up.content, content, MAX_MSG_LEN);
        up.session_id = session_id;
        ss_send_sentence_update(&red, &up);
    }
}

void handle_delete(const char* filename) {
    int nm_sock = connect_to_server(nm_ip, nm_port);
    if (nm_sock == -1) return;
    PacketHeader h;
    FileRequestPayload p;
    h.type = MSG_DELETE_FILE;
    h.size = sizeof(p);
    memset(&p, 0, sizeof(p));
    strncpy(p.filename, filename, MAX_PATH_LEN);
    strncpy(p.username, username, MAX_USERNAME_LEN);
    write(nm_sock, &h, sizeof(h));
    write(nm_sock, &p, sizeof(p));
    wait_for_response(nm_sock);
    close(nm_sock);
}

void handle_stream(const char* filename) {
    int nm_sock = connect_to_server(nm_ip, nm_port);
    if (nm_sock == -1) return;
    PacketHeader req_h;
    FileRequestPayload req_p;
    req_h.type = MSG_STREAM_FILE;
    req_h.size = sizeof(req_p);
    memset(&req_p, 0, sizeof(req_p));
    strncpy(req_p.filename, filename, MAX_PATH_LEN);
    strncpy(req_p.username, username, MAX_USERNAME_LEN);
    write(nm_sock, &req_h, sizeof(req_h));
    write(nm_sock, &req_p, sizeof(req_p));
    PacketHeader res_h;
    read(nm_sock, &res_h, sizeof(res_h));
    if (res_h.type == MSG_ERROR) {
        ResponsePayload err;
        read(nm_sock, &err, res_h.size);
        printf("SERVER ERROR: %s\n", err.message);
        close(nm_sock);
        return;
    }
    SSRedirectPayload red;
    read(nm_sock, &red, res_h.size);
    close(nm_sock);
    printf("Connecting to Storage Server at %s:%d for streaming...\n", red.ip_addr, red.port);
    int ss = connect_to_server(red.ip_addr, red.port);
    if (ss == -1) return;
    req_h.type = MSG_SS_STREAM_FILE;
    req_h.size = sizeof(req_p);
    write(ss, &req_h, sizeof(req_h));
    write(ss, &req_p, sizeof(req_p));
    PacketHeader init_h;
    ResponsePayload init_p;
    if (read(ss, &init_h, sizeof(init_h)) <= 0) {
        printf("ERROR: Storage Server disconnected.\n");
        close(ss);
        return;
    }
    read(ss, &init_p, init_h.size);
    if (init_h.type != MSG_SUCCESS) {
        printf("ERROR: %s\n", init_p.message);
        close(ss);
        return;
    }
    printf("--- Streaming File Content ---\n");
    while (1) {
        PacketHeader wh;
        ResponsePayload wp;
        if (read(ss, &wh, sizeof(wh)) <= 0) {
            printf("\nERROR: Storage Server disconnected mid-streaming.\n");
            break;
        }
        if (read(ss, &wp, wh.size) <= 0) {
            printf("\nERROR: Storage Server disconnected mid-streaming.\n");
            break;
        }
        if (wh.type == MSG_STREAM_END) {
            break;
        } else if (wh.type == MSG_STREAM_WORD) {
            printf("%s ", wp.message);
            fflush(stdout);
        } else {
            printf("\nERROR: Unexpected stream packet type %d\n", wh.type);
            break;
        }
    }
    printf("\n--- End of Stream ---\n");
    close(ss);
}

void handle_add_access(const char* filename, const char* target_user, const char* access) {
    int nm_sock = connect_to_server(nm_ip, nm_port);
    if (nm_sock == -1) return;
    PacketHeader h;
    AccessPayload p;
    h.type = MSG_ADD_ACCESS;
    h.size = sizeof(p);
    memset(&p, 0, sizeof(p));
    strncpy(p.filename, filename, MAX_PATH_LEN);
    strncpy(p.requestor_username, username, MAX_USERNAME_LEN);
    strncpy(p.target_username, target_user, MAX_USERNAME_LEN);
    p.access_type = (strcmp(access, "W") == 0 || strcmp(access, "w") == 0) ? 1 : 0;
    write(nm_sock, &h, sizeof(h));
    write(nm_sock, &p, sizeof(p));
    wait_for_response(nm_sock);
    close(nm_sock);
}

void handle_rem_access(const char* filename, const char* target_user) {
    int nm_sock = connect_to_server(nm_ip, nm_port);
    if (nm_sock == -1) return;
    PacketHeader h;
    AccessPayload p;
    h.type = MSG_REM_ACCESS;
    h.size = sizeof(p);
    memset(&p, 0, sizeof(p));
    strncpy(p.filename, filename, MAX_PATH_LEN);
    strncpy(p.requestor_username, username, MAX_USERNAME_LEN);
    strncpy(p.target_username, target_user, MAX_USERNAME_LEN);
    write(nm_sock, &h, sizeof(h));
    write(nm_sock, &p, sizeof(p));
    wait_for_response(nm_sock);
    close(nm_sock);
}

void handle_undo(const char* filename) {
    int nm_sock = connect_to_server(nm_ip, nm_port);
    if (nm_sock == -1) return;
    PacketHeader h;
    FileRequestPayload p;
    h.type = MSG_SS_UNDO;
    h.size = sizeof(p);
    memset(&p, 0, sizeof(p));
    strncpy(p.filename, filename, MAX_PATH_LEN);
    strncpy(p.username, username, MAX_USERNAME_LEN);
    write(nm_sock, &h, sizeof(h));
    write(nm_sock, &p, sizeof(p));
    wait_for_response(nm_sock);
    close(nm_sock);
}

void handle_info(const char* filename) {
    int nm_sock = connect_to_server(nm_ip, nm_port);
    if (nm_sock == -1) return;
    PacketHeader h;
    FileRequestPayload p;
    h.type = MSG_INFO_FILE;
    h.size = sizeof(p);
    memset(&p, 0, sizeof(p));
    strncpy(p.filename, filename, MAX_PATH_LEN);
    strncpy(p.username, username, MAX_USERNAME_LEN);
    write(nm_sock, &h, sizeof(h));
    write(nm_sock, &p, sizeof(p));
    PacketHeader rh;
    ResponsePayload rp;
    if (read(nm_sock, &rh, sizeof(rh)) > 0 && read(nm_sock, &rp, rh.size) > 0) {
        if (rh.type == MSG_SUCCESS)
            printf("SERVER: %s\n", rp.message);
        else
            printf("SERVER ERROR: %s\n", rp.message);
    } else {
        printf("SERVER ERROR: No response.\n");
    }
    close(nm_sock);
}

void handle_view(int list_all, int with_details) {
    int nm_sock = connect_to_server(nm_ip, nm_port);
    if (nm_sock == -1) return;
    PacketHeader h;
    ViewRequestPayload p;
    h.type = MSG_VIEW_FILES;
    h.size = sizeof(p);
    memset(&p, 0, sizeof(p));
    strncpy(p.username, username, MAX_USERNAME_LEN);
    p.list_all = list_all;
    p.with_details = with_details;
    write(nm_sock, &h, sizeof(h));
    write(nm_sock, &p, sizeof(p));
    PacketHeader rh;
    ResponsePayload rp;
    if (read(nm_sock, &rh, sizeof(rh)) > 0 && read(nm_sock, &rp, rh.size) > 0) {
        if (rh.type == MSG_SUCCESS)
            printf("%s", rp.message);
        else
            printf("SERVER ERROR: %s\n", rp.message);
    } else {
        printf("SERVER ERROR: No response.\n");
    }
    close(nm_sock);
}

void handle_list() {
    int nm_sock = connect_to_server(nm_ip, nm_port);
    if (nm_sock == -1) return;
    PacketHeader h;
    h.type = MSG_LIST_USERS;
    h.size = 0;
    write(nm_sock, &h, sizeof(h));
    wait_for_response(nm_sock);
    close(nm_sock);
}

void handle_reset_users() {
    int nm_sock = connect_to_server(nm_ip, nm_port);
    if (nm_sock == -1) return;
    PacketHeader h; FileRequestPayload p; h.type = MSG_RESET_USERS; h.size = sizeof(p);
    memset(&p,0,sizeof(p)); strncpy(p.username, username, MAX_USERNAME_LEN); // filename unused
    write(nm_sock,&h,sizeof(h)); write(nm_sock,&p,sizeof(p)); wait_for_response(nm_sock); close(nm_sock);
}

void handle_exec(const char* filename) {
    int nm_sock = connect_to_server(nm_ip, nm_port);
    if (nm_sock == -1) return;
    PacketHeader req_h;
    FileRequestPayload req_p;
    req_h.type = MSG_EXEC_FILE;
    req_h.size = sizeof(req_p);
    memset(&req_p, 0, sizeof(req_p));
    strncpy(req_p.filename, filename, MAX_PATH_LEN);
    strncpy(req_p.username, username, MAX_USERNAME_LEN);
    write(nm_sock, &req_h, sizeof(req_h));
    write(nm_sock, &req_p, sizeof(req_p));
    PacketHeader res_h;
    ResponsePayload res_p;
    if (read(nm_sock, &res_h, sizeof(res_h)) <= 0) {
        printf("SERVER ERROR: No response.\n");
        close(nm_sock);
        return;
    }
    if (read(nm_sock, &res_p, res_h.size) <= 0) {
        printf("SERVER ERROR: Incomplete response.\n");
        close(nm_sock);
        return;
    }
    if (res_h.type == MSG_SUCCESS)
        printf("SERVER: %s\n", res_p.message);
    else
        printf("SERVER ERROR: %s\n", res_p.message);
    close(nm_sock);
}

// --- Folder hierarchy ---
void handle_create_folder(const char* folder) {
    int nm_sock = connect_to_server(nm_ip, nm_port);
    if (nm_sock == -1) return;
    PacketHeader h;
    FolderRequestPayload p;
    h.type = MSG_CREATE_FOLDER;
    h.size = sizeof(p);
    memset(&p, 0, sizeof(p));
    strncpy(p.username, username, MAX_USERNAME_LEN);
    strncpy(p.folder, folder, MAX_PATH_LEN);
    write(nm_sock, &h, sizeof(h));
    write(nm_sock, &p, sizeof(p));
    wait_for_response(nm_sock);
    close(nm_sock);
}

void handle_move_file(const char* filename, const char* folder) {
    int nm_sock = connect_to_server(nm_ip, nm_port);
    if (nm_sock == -1) return;
    PacketHeader h;
    MoveRequestPayload p;
    h.type = MSG_MOVE_FILE;
    h.size = sizeof(p);
    memset(&p, 0, sizeof(p));
    strncpy(p.username, username, MAX_USERNAME_LEN);
    strncpy(p.filename, filename, MAX_PATH_LEN);
    strncpy(p.folder, folder, MAX_PATH_LEN);
    write(nm_sock, &h, sizeof(h));
    write(nm_sock, &p, sizeof(p));
    wait_for_response(nm_sock);
    close(nm_sock);
}

void handle_view_folder(const char* folder) {
    int nm_sock = connect_to_server(nm_ip, nm_port);
    if (nm_sock == -1) return;
    PacketHeader h;
    ViewFolderPayload p;
    h.type = MSG_VIEW_FOLDER;
    h.size = sizeof(p);
    memset(&p, 0, sizeof(p));
    strncpy(p.username, username, MAX_USERNAME_LEN);
    strncpy(p.folder, folder, MAX_PATH_LEN);
    write(nm_sock, &h, sizeof(h));
    write(nm_sock, &p, sizeof(p));
    PacketHeader rh;
    ResponsePayload rp;
    if (read(nm_sock, &rh, sizeof(rh)) > 0 && read(nm_sock, &rp, rh.size) > 0) {
        if (rh.type == MSG_SUCCESS)
            printf("%s", rp.message);
        else
            printf("SERVER ERROR: %s\n", rp.message);
    } else {
        printf("SERVER ERROR: No response.\n");
    }
    close(nm_sock);
}

void handle_delete_folder(const char* folder) {
    int nm_sock = connect_to_server(nm_ip, nm_port);
    if (nm_sock == -1) return;
    if (strcmp(folder, ".") == 0 || strcmp(folder, "/") == 0) {
        printf("Error: Cannot delete root folder.\n");
        close(nm_sock);
        return;
    }
    PacketHeader h;
    FolderRequestPayload p;
    h.type = MSG_DELETE_FOLDER;
    h.size = sizeof(p);
    memset(&p, 0, sizeof(p));
    strncpy(p.username, username, MAX_USERNAME_LEN);
    strncpy(p.folder, folder, MAX_PATH_LEN);
    write(nm_sock, &h, sizeof(h));
    write(nm_sock, &p, sizeof(p));
    wait_for_response(nm_sock);
    close(nm_sock);
}
