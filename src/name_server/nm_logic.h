#ifndef NM_LOGIC_H
#define NM_LOGIC_H

#include "../common/protocol.h"

void nm_logic_init();
void nm_start_heartbeat_monitor();

void nm_handle_ss_registration(int sock);
void nm_handle_create_file(int client_sock);
void nm_handle_file_redirect(int client_sock, MessageType type);
void nm_handle_delete_file(int client_sock);
void nm_handle_add_access(int client_sock);
void nm_handle_rem_access(int client_sock);
void nm_handle_view_files(int client_sock);
void nm_handle_undo(int client_sock);
void nm_handle_info(int client_sock);
void nm_handle_stream(int client_sock);
void nm_register_user(const char* username, int client_sock);
void nm_handle_list_users(int client_sock);
void nm_handle_exec(int client_sock);
void nm_handle_reset_users(int client_sock);
// Bonus access request workflow handlers
void nm_handle_request_access(int client_sock);
void nm_handle_list_access_requests(int client_sock);
void nm_handle_decide_access(int client_sock);
void nm_handle_list_owner_files(int client_sock);
// Checkpoint handlers
void nm_handle_checkpoint(int client_sock);
void nm_handle_view_checkpoint(int client_sock);
void nm_handle_revert_checkpoint(int client_sock);
void nm_handle_list_checkpoints(int client_sock);

// Folder hierarchy handlers
void nm_handle_create_folder(int client_sock);
void nm_handle_move_file(int client_sock);
void nm_handle_view_folder(int client_sock);
void nm_handle_delete_folder(int client_sock);

#endif // NM_LOGIC_H
