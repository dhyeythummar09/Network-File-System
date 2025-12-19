#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <pthread.h>
#include <signal.h>
// For directory scanning
#include <dirent.h>
#include <sys/stat.h>
// Core protocol and common helpers
#include "../common/protocol.h"
#include "../common/network.h"
#include "../common/logger.h"
#include "ss_logic.h"

// Global server socket for cleanup
static int global_server_sock = -1;
static volatile sig_atomic_t shutdown_requested = 0;
static volatile sig_atomic_t nm_disconnected = 0;
static char stored_nm_ip[16];
static int stored_nm_port = 0;

// This server's port (read from command line)
int my_client_port; 

// Logic has been moved to ss_logic.c; this file now focuses on server I/O and dispatch

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
 * Monitor Name Server connectivity
 */
static void* monitor_nm_thread(void* arg) {
    (void)arg;
    while (!shutdown_requested && !nm_disconnected) {
        sleep(3); // Check every 3 seconds
        int test_sock = socket(PF_INET, SOCK_STREAM, 0);
        if (test_sock == -1) continue;
        
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = inet_addr(stored_nm_ip);
        addr.sin_port = htons(stored_nm_port);
        
        struct timeval timeout;
        timeout.tv_sec = 2;
        timeout.tv_usec = 0;
        setsockopt(test_sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        setsockopt(test_sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
        
        if (connect(test_sock, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
            close(test_sock);
            nm_disconnected = 1;
            printf("\n[ERROR] Name Server disconnected! Storage Server terminating...\n");
            exit(0); // Immediately terminate the process
        }
        close(test_sock);
    }
    return NULL;
}

/**
 * The main function for each connection thread.
 */
void* handle_connection(void* arg) {
    int sock = *((int*)arg);
    free(arg);

    PacketHeader header;
    memset(&header, 0, sizeof(header));
    
    if (read_all(sock, &header, sizeof(header)) == -1) {
        // Silent: likely a heartbeat check from Name Server (connects then immediately closes)
        close(sock);
        return NULL;
    }

    // Route to the correct handler
    switch (header.type) {
        case MSG_SS_CREATE_FILE: // From Name Server
            ss_handle_create_file(sock);
            break;
        case MSG_SS_READ_FILE:   // From Client
            ss_handle_read_file(sock);
            break;
        case MSG_SS_WRITE_FILE:  // From Client
            ss_handle_write_file(sock);
            break;
        case MSG_SS_DELETE_FILE: // From Name Server
            ss_handle_delete_file(sock);
            break;
        case MSG_SS_WRITE_SENTENCE:
            ss_handle_write_sentence(sock);
            break;
        case MSG_SS_ETIRW:
            ss_handle_etirw(sock);
            break;
        case MSG_SS_UNDO:
            ss_handle_undo(sock);
            break;
        case MSG_SS_STREAM_FILE:
            ss_handle_stream_file(sock);
            break;
        case MSG_SS_EXEC_FILE:
            ss_handle_exec_file(sock);
            break;
        case MSG_SS_CHECKPOINT_CREATE:
            ss_handle_checkpoint_create(sock);
            break;
        case MSG_SS_CHECKPOINT_VIEW:
            ss_handle_checkpoint_view(sock);
            break;
        case MSG_SS_CHECKPOINT_REVERT:
            ss_handle_checkpoint_revert(sock);
            break;
        case MSG_SS_CHECKPOINT_LIST:
            ss_handle_checkpoint_list(sock);
            break;
        case MSG_SS_CREATE_FOLDER:
            ss_handle_create_folder(sock);
            break;
        case MSG_SS_MOVE_FILE:
            ss_handle_move_file(sock);
            break;
        case MSG_SS_VIEW_FOLDER:
            ss_handle_view_folder(sock);
            break;
        case MSG_SS_DELETE_FOLDER:
            ss_handle_delete_folder(sock);
            break;
        default:
            fprintf(stderr, "SS Error: Unknown message type: %d\n", header.type);
    }
    
    close(sock); 
    return NULL;
}


/**
 * Connects to the Name Server to register this Storage Server.
 */
void register_with_nm(const char* my_ip, const char* nm_ip, int nm_port) {
    int sock;
    struct sockaddr_in nm_addr;
    
    sock = socket(PF_INET, SOCK_STREAM, 0);
    memset(&nm_addr, 0, sizeof(nm_addr));
    
    nm_addr.sin_family = AF_INET;
    nm_addr.sin_addr.s_addr = inet_addr(nm_ip);
    nm_addr.sin_port = htons(nm_port);

    if (connect(sock, (struct sockaddr*)&nm_addr, sizeof(nm_addr)) == -1) {
        perror("connect() error"); exit(1);
    }
    printf("Connected to Name Server.\n");

    PacketHeader header;
    header.type = MSG_SS_REGISTER;
    header.size = sizeof(SSRegisterPayload);
    
    SSRegisterPayload payload; memset(&payload, 0, sizeof(payload));
    strncpy(payload.ip_addr, my_ip, sizeof(payload.ip_addr)); 
    payload.nm_port = nm_port;
    payload.client_port = my_client_port;
    payload.num_files = 0;
    payload.files_blob[0] = '\0';

    // Build a newline-separated list of .txt files in current directory
    DIR* dir = opendir(".");
    if (dir) {
        struct dirent* entry;
        while ((entry = readdir(dir)) != NULL) {
            const char* name = entry->d_name;
            // Skip hidden entries and directories
            if (name[0] == '.') continue;
            struct stat st; if (stat(name, &st) != 0) continue;
            if (!S_ISREG(st.st_mode)) continue;
            // Only include simple text files to avoid polluting index
            const char* dot = strrchr(name, '.');
            if (!dot || strcmp(dot, ".txt") != 0) continue;
            // Append to blob if space permits
            size_t need = strlen(payload.files_blob) + strlen(name) + 2;
            if (need < sizeof(payload.files_blob)) {
                if (payload.files_blob[0] != '\0') strcat(payload.files_blob, "\n");
                strcat(payload.files_blob, name);
                payload.num_files++;
            } else {
                // No more space; stop collecting
                break;
            }
        }
        closedir(dir);
    }

    write(sock, &header, sizeof(header));
    write(sock, &payload, sizeof(payload));
    
    printf("Registration information sent (Port: %d, files reported: %d).\n", my_client_port, payload.num_files);
    close(sock);
}


/**
 * Main entry point for the Storage Server.
 */
int main(int argc, char *argv[]) {
    if (argc != 5) {
        fprintf(stderr, "Usage: %s <my_ip> <name_server_ip> <name_server_port> <my_client_port>\n", argv[0]);
        exit(1);
    }
    
    char* my_ip = argv[1];
    char* nm_ip = argv[2];
    int nm_port = atoi(argv[3]);
    if (nm_port <= 0 || nm_port > 65535) { fprintf(stderr, "Invalid Name Server port: %s\n", argv[3]); exit(1);} 
    my_client_port = atoi(argv[4]); 
    if (my_client_port <= 0 || my_client_port > 65535) { fprintf(stderr, "Invalid Storage Server port: %s\n", argv[4]); exit(1);} 

    // Store NM info for monitoring
    strncpy(stored_nm_ip, nm_ip, sizeof(stored_nm_ip) - 1);
    stored_nm_port = nm_port;

    // Set up signal handlers for graceful shutdown
    signal(SIGINT, handle_shutdown_signal);
    signal(SIGTERM, handle_shutdown_signal);
    // Prevent process termination on EPIPE when peer closes early (e.g., NM closes without reading)
    signal(SIGPIPE, SIG_IGN);

    register_with_nm(my_ip, nm_ip, nm_port);

    // Start Name Server monitoring thread
    pthread_t monitor_tid;
    if (pthread_create(&monitor_tid, NULL, monitor_nm_thread, NULL) == 0) {
        pthread_detach(monitor_tid);
    }

    int server_sock;
    struct sockaddr_in server_addr;
    
    server_sock = socket(PF_INET, SOCK_STREAM, 0);
    global_server_sock = server_sock;
    
    // Set SO_REUSEADDR to allow quick restart
    int opt = 1;
    if (setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1) {
        perror("setsockopt() warning");
    }
    
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(my_client_port);
    
    if (bind(server_sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
        perror("SS bind() error"); exit(1);
    }
    
    if (listen(server_sock, 5) == -1) {
        perror("SS listen() error"); exit(1);
    }
    
    printf("Storage Server started. Listening for connections on port %d...\n", my_client_port);

    while (!shutdown_requested) {
        struct sockaddr_in client_addr;
        socklen_t client_addr_size = sizeof(client_addr);
        
        int sock = accept(server_sock, (struct sockaddr*)&client_addr, &client_addr_size);
        
        if (sock == -1) {
            if (shutdown_requested) {
                break;
            }
            perror("SS accept() error");
            continue;
        }

        pthread_t tid;
        int* p_sock = malloc(sizeof(int));
        *p_sock = sock;
        
        if (pthread_create(&tid, NULL, handle_connection, (void*)p_sock) != 0) {
            perror("SS pthread_create() error");
            free(p_sock);
            close(sock);
        }
        pthread_detach(tid); 
    }
    
    // Graceful shutdown
    if (shutdown_requested) {
        printf("\n");
        if (nm_disconnected) {
            printf("Storage Server terminated due to Name Server disconnection.\n");
        } else {
            printf("Storage Server shutting down gracefully...\n");
            printf("Storage Server stopped.\n");
        }
    }
    
    close(server_sock);
    return 0;
}