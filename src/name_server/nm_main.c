#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <pthread.h>
#include <signal.h>
#include "../common/protocol.h"
#include "../common/network.h"
#include "../common/logger.h"
#include "nm_logic.h"

// Global server socket for cleanup
static int global_server_sock = -1;
static volatile sig_atomic_t shutdown_requested = 0;

/**
 * Signal handler for graceful shutdown
 */
void handle_shutdown_signal(int sig) {
    (void)sig;  // Unused parameter
    shutdown_requested = 1;
    if (global_server_sock != -1) {
        close(global_server_sock);
    }
}

/**
 * The main function for each connection thread.
 */
void* handle_connection(void* arg) {
    int client_sock = *((int*)arg);
    free(arg);
    
    // Get client address information for logging
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    char client_ip[INET_ADDRSTRLEN] = "unknown";
    int client_port = 0;
    if (getpeername(client_sock, (struct sockaddr*)&addr, &addr_len) == 0) {
        inet_ntop(AF_INET, &addr.sin_addr, client_ip, INET_ADDRSTRLEN);
        client_port = ntohs(addr.sin_port);
    } 

    PacketHeader header;
    memset(&header, 0, sizeof(header));
    
    if (read_all(client_sock, &header, sizeof(header)) == -1) {
        // Silently ignore - this is expected for heartbeat/monitoring connections
        close(client_sock);
        return NULL;
    }

    switch (header.type) {
        case MSG_CLIENT_REGISTER: { 
            ClientRegisterPayload payload;
            memset(&payload, 0, sizeof(payload));
            if (read_all(client_sock, &payload, sizeof(payload)) == -1) {
                 fprintf(stderr, "Failed to read client register payload.\n");
                 break;
            }
            LOG_REQUEST(client_ip, client_port, payload.username, "REGISTRATION: Client connected (nm_port=%d, ss_port=%d)", payload.nm_port, payload.ss_port);
            nm_register_user(payload.username, client_sock);
            break;
        }
        case MSG_CLIENT_DISCONNECT: {
            ClientRegisterPayload payload;
            memset(&payload, 0, sizeof(payload));
            if (read_all(client_sock, &payload, sizeof(payload)) == -1) {
                 fprintf(stderr, "Failed to read client disconnect payload.\n");
                 break;
            }
            LOG_INFO("DISCONNECTION: Client '%s' (%s:%d) disconnected", payload.username, client_ip, client_port);
            // Send acknowledgment
            PacketHeader ack_h; ResponsePayload ack_p;
            ack_h.type = MSG_SUCCESS; ack_h.size = sizeof(ack_p);
            snprintf(ack_p.message, sizeof(ack_p.message), "Goodbye!");
            write_all(client_sock, &ack_h, sizeof(ack_h));
            write_all(client_sock, &ack_p, sizeof(ack_p));
            break;
        }
        case MSG_SS_REGISTER:
            LOG_INFO("Storage Server connecting from %s:%d", client_ip, client_port);
            nm_handle_ss_registration(client_sock);
            break;
        case MSG_CREATE_FILE:
            nm_handle_create_file(client_sock);
            break;
        case MSG_READ_FILE:
        case MSG_WRITE_FILE:
            nm_handle_file_redirect(client_sock, header.type);
            break;
        case MSG_DELETE_FILE:
            nm_handle_delete_file(client_sock);
            break;
            
        // --- NEW CASES ---
        case MSG_ADD_ACCESS:
            nm_handle_add_access(client_sock);
            break;
        case MSG_REM_ACCESS:
            nm_handle_rem_access(client_sock);
            break;
        case MSG_VIEW_FILES:
            nm_handle_view_files(client_sock);
            break;
        case MSG_SS_UNDO:
            nm_handle_undo(client_sock);
            break;
        case MSG_INFO_FILE:
            nm_handle_info(client_sock);
            break;
        case MSG_STREAM_FILE:
            nm_handle_stream(client_sock);
            break;
        case MSG_LIST_USERS:
            nm_handle_list_users(client_sock);
            break;
        case MSG_EXEC_FILE:
            nm_handle_exec(client_sock);
            break;
        case MSG_REQUEST_ACCESS:
            nm_handle_request_access(client_sock);
            break;
        case MSG_LIST_ACCESS_REQUESTS:
            nm_handle_list_access_requests(client_sock);
            break;
        case MSG_DECIDE_ACCESS:
            nm_handle_decide_access(client_sock);
            break;
        case MSG_LIST_OWNER_FILES:
            nm_handle_list_owner_files(client_sock);
            break;
        case MSG_CHECKPOINT:
            nm_handle_checkpoint(client_sock);
            break;
        case MSG_VIEW_CHECKPOINT:
            nm_handle_view_checkpoint(client_sock);
            break;
        case MSG_REVERT_CHECKPOINT:
            nm_handle_revert_checkpoint(client_sock);
            break;
        case MSG_LIST_CHECKPOINTS:
            nm_handle_list_checkpoints(client_sock);
            break;
        case MSG_CREATE_FOLDER:
            nm_handle_create_folder(client_sock);
            break;
        case MSG_MOVE_FILE:
            nm_handle_move_file(client_sock);
            break;
        case MSG_VIEW_FOLDER:
            nm_handle_view_folder(client_sock);
            break;
        case MSG_DELETE_FOLDER:
            nm_handle_delete_folder(client_sock);
            break;
        case MSG_RESET_USERS:
            nm_handle_reset_users(client_sock);
            break;
        // --- END NEW ---
            
        default:
            fprintf(stderr, "Error: Unknown message type received: %d\n", header.type);
            break;
    }

    close(client_sock); 
    return NULL;
}


/**
 * Main entry point for the Name Server.
 */
int main(int argc, char* argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <port>\n", argv[0]);
        return 1;
    }
    int nm_port = atoi(argv[1]);
    if (nm_port <= 0 || nm_port > 65535) {
        fprintf(stderr, "Invalid port: %s\n", argv[1]);
        return 1;
    }

    // Set up signal handlers for graceful shutdown
    signal(SIGINT, handle_shutdown_signal);
    signal(SIGTERM, handle_shutdown_signal);

    nm_logic_init();
    nm_start_heartbeat_monitor();
    int server_sock;
    struct sockaddr_in server_addr;
    // Prevent termination on SIGPIPE when clients or SS close early
    signal(SIGPIPE, SIG_IGN);
    // 1. Create the server socket
    server_sock = socket(PF_INET, SOCK_STREAM, 0);
    global_server_sock = server_sock;
    
    // Set SO_REUSEADDR to allow quick restart
    int opt = 1;
    if (setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1) {
        perror("setsockopt() warning");
    }
    
    // 2. Bind the socket
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY); 
    server_addr.sin_port = htons(nm_port);
    
    if (bind(server_sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
        perror("bind() error"); exit(1);
    }
    
    // 3. Start listening
    if (listen(server_sock, 5) == -1) {
        perror("listen() error"); exit(1);
    }
    
    LOG_INFO("Name Server started. Waiting for connections on port %d...", nm_port);

    // 4. Accept connections in a loop
    while (!shutdown_requested) {
        struct sockaddr_in client_addr;
        socklen_t client_addr_size = sizeof(client_addr);
        
        int client_sock = accept(server_sock, (struct sockaddr*)&client_addr, &client_addr_size);
        
        if (client_sock == -1) {
            if (shutdown_requested) {
                break;
            }
            perror("accept() error");
            continue; 
        }

        pthread_t tid;
        int* p_client_sock = malloc(sizeof(int));
        *p_client_sock = client_sock;
        
        if (pthread_create(&tid, NULL, handle_connection, (void*)p_client_sock) != 0) {
            perror("pthread_create() error");
            free(p_client_sock);
            close(client_sock);
        }
        pthread_detach(tid); 
    }
    
    // Graceful shutdown
    if (shutdown_requested) {
        printf("\n");
        LOG_INFO("Name Server shutting down gracefully...");
        // TODO: Notify connected storage servers and clients
        printf("Name Server stopped.\n");
    }
    
    close(server_sock);
    return 0;
}