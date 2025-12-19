#ifndef CLIENT_LOGIC_H
#define CLIENT_LOGIC_H

#include "../common/protocol.h"

// Global state defined in client_main.c
extern char username[MAX_USERNAME_LEN];
extern char nm_ip[16];
extern int nm_port;

int connect_to_server(const char* ip, int port);
int wait_for_response_get_status(int sock);
void wait_for_response(int sock);
int iequals(const char* a, const char* b);

// Registration
void register_with_nm();

// File operations
void handle_create(const char* filename);
void handle_read(const char* filename);
void handle_write(const char* filename, const char* content);
void handle_write_sentence(const char* filename, int sentence_number);
void handle_delete(const char* filename);
void handle_stream(const char* filename);
void handle_list();
void handle_exec(const char* filename);
void handle_reset_users();

// Access control
void handle_add_access(const char* filename, const char* target_user, const char* access);
void handle_rem_access(const char* filename, const char* target_user);
void handle_undo(const char* filename);
void handle_info(const char* filename);

// New features
void handle_view(int list_all, int with_details);

// Folder hierarchy
void handle_create_folder(const char* folder);
void handle_move_file(const char* filename, const char* folder);
void handle_view_folder(const char* folder);
void handle_delete_folder(const char* folder);

#endif // CLIENT_LOGIC_H
