#ifndef SS_LOGIC_H
#define SS_LOGIC_H

#include "../common/protocol.h"

void ss_handle_create_file(int sock);
void ss_handle_read_file(int sock);
void ss_handle_write_file(int sock);
void ss_handle_delete_file(int sock);
void ss_handle_write_sentence(int sock);
void ss_handle_etirw(int sock);
void ss_handle_undo(int sock);
void ss_handle_stream_file(int sock);
void ss_handle_exec_file(int sock);
// Checkpoint handlers
void ss_handle_checkpoint_create(int sock);
void ss_handle_checkpoint_view(int sock);
void ss_handle_checkpoint_revert(int sock);
void ss_handle_checkpoint_list(int sock);

// Folders
void ss_handle_create_folder(int sock);
void ss_handle_move_file(int sock);
void ss_handle_view_folder(int sock);
void ss_handle_delete_folder(int sock);

#endif // SS_LOGIC_H
