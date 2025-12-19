#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <signal.h>
#include <pthread.h>
#include "../common/protocol.h"
#include "client_logic.h"

char username[MAX_USERNAME_LEN];
char nm_ip[16];
int nm_port = 0; // runtime-provided NM port (made non-static for logic module)
static volatile sig_atomic_t interrupted = 0; // Set when Ctrl-C received
static volatile sig_atomic_t nm_disconnected = 0; // Set when NM is unreachable

static void handle_sigint(int sig) {
    (void)sig;
    interrupted = 1;
    const char* msg = "\nClient interrupt received. Exiting gracefully...\n";
    write(STDOUT_FILENO, msg, strlen(msg));
}

// Monitor Name Server connectivity
static void* monitor_nm_thread(void* arg) {
    (void)arg;
    while (!interrupted && !nm_disconnected) {
        sleep(3); // Check every 3 seconds
        int test_sock = socket(PF_INET, SOCK_STREAM, 0);
        if (test_sock == -1) continue;
        
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = inet_addr(nm_ip);
        addr.sin_port = htons(nm_port);
        
        struct timeval timeout;
        timeout.tv_sec = 2;
        timeout.tv_usec = 0;
        setsockopt(test_sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        setsockopt(test_sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
        
        if (connect(test_sock, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
            close(test_sock);
            nm_disconnected = 1;
            const char* msg = "\n[ERROR] Name Server disconnected! Client terminating...\n";
            write(STDOUT_FILENO, msg, strlen(msg));
            exit(0); // Immediately terminate the process
        }
        close(test_sock);
    }
    return NULL;
}
// NOTE: All client operation handlers and helpers have been moved to
// client_logic.c. This file now only maintains global state, signal handling,
// and the interactive command loop delegating to logic functions.

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <name_server_ip> <name_server_port>\n", argv[0]);
        exit(1);
    }
    strncpy(nm_ip, argv[1], 16);
    nm_port = atoi(argv[2]);
    if (nm_port <= 0 || nm_port > 65535) {
        fprintf(stderr, "Invalid Name Server port: %s\n", argv[2]);
        exit(1);
    }

    printf("Enter username: ");
    fgets(username, MAX_USERNAME_LEN, stdin);
    username[strcspn(username, "\n")] = 0; // Remove newline

    register_with_nm();

    // Install SIGINT handler for graceful Ctrl-C exit
    struct sigaction sa; memset(&sa, 0, sizeof(sa)); sa.sa_handler = handle_sigint; sigemptyset(&sa.sa_mask); sigaction(SIGINT, &sa, NULL);

    // Start Name Server monitoring thread
    pthread_t monitor_tid;
    if (pthread_create(&monitor_tid, NULL, monitor_nm_thread, NULL) == 0) {
        pthread_detach(monitor_tid);
    }

    // --- Main Command Loop ---
    char line[MAX_MSG_LEN];
    while (!interrupted && !nm_disconnected) {
        printf("client> ");
        if (!fgets(line, sizeof(line), stdin)) {
            break; // Exit on EOF (Ctrl+D)
        }
        
        line[strcspn(line, "\n")] = 0; // Remove newline

        char* command = strtok(line, " ");
        if (!command) continue;

        if (iequals(command, "create")) {
            char* opt = strtok(NULL, " ");
            if (!opt) { printf("Usage: create [-f] <filename>\n"); continue; }
            if (strcmp(opt, "-f")==0) {
                char* filename = strtok(NULL, " ");
                if (!filename) { printf("Usage: create -f <filename>\n"); continue; }
                // force: try delete (ignore errors), then create
                handle_delete(filename); // may error if not exists; that's fine
                handle_create(filename);
            } else {
                char* filename = opt;
                handle_create(filename);
            }
        } else if (iequals(command, "read")) {
            char* filename = strtok(NULL, " ");
            if (filename) {
                handle_read(filename);
            } else {
                printf("Usage: read <filename>\n");
            }
        } else if (iequals(command, "write")) {
            char* filename = strtok(NULL, " ");
            char* arg2 = strtok(NULL, ""); // Either content or sentence_number ...
            if (!filename || !arg2) { printf("Usage: write <filename> <content|sentence_number>\n"); continue; }
            // If arg2 begins with digits only, treat as sentence_number
            int digits = 1; for (const char* p = arg2; *p; ++p) { if (!isdigit((unsigned char)*p) && !isspace((unsigned char)*p)) { digits = 0; break; } }
            if (digits) {
                int sentence_number = atoi(arg2);
                handle_write_sentence(filename, sentence_number);
            } else {
                // whole-file write (legacy)
                handle_write(filename, arg2);
            }
        }
        else if (iequals(command, "delete")) {
            char* filename = strtok(NULL, " ");
            if (filename) {
                handle_delete(filename);
            } else {
                printf("Usage: delete <filename>\n");
            }
        }
        // --- NEW Commands ---
        else if (iequals(command, "view")) {
            // Parse flags: -a, -l, -al
            char* flags = strtok(NULL, " ");
            int list_all = 0, with_details = 0;
            if (flags) {
                if (strcmp(flags, "-a") == 0) list_all = 1;
                else if (strcmp(flags, "-l") == 0) with_details = 1;
                else if (strcmp(flags, "-al") == 0 || strcmp(flags, "-la") == 0) { list_all = 1; with_details = 1; }
            }
            handle_view(list_all, with_details);
        }
        else if (iequals(command, "myfiles")) {
            int nm_sock = connect_to_server(nm_ip, nm_port);
            if (nm_sock == -1) continue;
            PacketHeader h; OwnerFilesQueryPayload q; h.type = MSG_LIST_OWNER_FILES; h.size = sizeof(q);
            memset(&q,0,sizeof(q)); strncpy(q.owner_username, username, MAX_USERNAME_LEN);
            write(nm_sock, &h, sizeof(h)); write(nm_sock, &q, sizeof(q));
            PacketHeader rh; ResponsePayload rp;
            if (read(nm_sock, &rh, sizeof(rh))>0 && read(nm_sock, &rp, rh.size)>0) {
                if (rh.type == MSG_SUCCESS) printf("%s", rp.message); else printf("SERVER ERROR: %s\n", rp.message);
            } else {
                printf("SERVER ERROR: No response.\n");
            }
            close(nm_sock);
        }
        else if (iequals(command, "checkpoint")) {
            char* filename = strtok(NULL, " "); char* tag = strtok(NULL, "");
            if (!filename || !tag) { printf("Usage: checkpoint <filename> <checkpoint_tag>\n"); }
            else {
                int nm_sock = connect_to_server(nm_ip, nm_port); if (nm_sock==-1) continue;
                PacketHeader h; CheckpointTagPayload p; h.type=MSG_CHECKPOINT; h.size=sizeof(p); memset(&p,0,sizeof(p));
                strncpy(p.username, username, MAX_USERNAME_LEN); strncpy(p.filename, filename, MAX_PATH_LEN); strncpy(p.tag, tag, sizeof(p.tag)-1);
                write(nm_sock,&h,sizeof(h)); write(nm_sock,&p,sizeof(p)); wait_for_response(nm_sock); close(nm_sock);
            }
        }
        else if (iequals(command, "viewcheckpoint")) {
            char* filename = strtok(NULL, " "); char* tag = strtok(NULL, "");
            if (!filename || !tag) { printf("Usage: viewcheckpoint <filename> <checkpoint_tag>\n"); }
            else {
                int nm_sock = connect_to_server(nm_ip, nm_port); if (nm_sock==-1) continue;
                PacketHeader h; CheckpointTagPayload p; h.type=MSG_VIEW_CHECKPOINT; h.size=sizeof(p); memset(&p,0,sizeof(p));
                strncpy(p.username, username, MAX_USERNAME_LEN); strncpy(p.filename, filename, MAX_PATH_LEN); strncpy(p.tag, tag, sizeof(p.tag)-1);
                write(nm_sock,&h,sizeof(h)); write(nm_sock,&p,sizeof(p));
                PacketHeader rh; ResponsePayload rp; if (read(nm_sock,&rh,sizeof(rh))>0 && read(nm_sock,&rp,rh.size)>0) {
                    if (rh.type==MSG_SUCCESS) { printf("---- checkpoint %s ----\n%s\n-------------------------\n", tag, rp.message); }
                    else { printf("SERVER ERROR: %s\n", rp.message); }
                } else { printf("SERVER ERROR: No response.\n"); }
                close(nm_sock);
            }
        }
        else if (iequals(command, "revert")) {
            char* filename = strtok(NULL, " "); char* tag = strtok(NULL, "");
            if (!filename || !tag) { printf("Usage: revert <filename> <checkpoint_tag>\n"); }
            else {
                int nm_sock = connect_to_server(nm_ip, nm_port); if (nm_sock==-1) continue;
                PacketHeader h; CheckpointTagPayload p; h.type=MSG_REVERT_CHECKPOINT; h.size=sizeof(p); memset(&p,0,sizeof(p));
                strncpy(p.username, username, MAX_USERNAME_LEN); strncpy(p.filename, filename, MAX_PATH_LEN); strncpy(p.tag, tag, sizeof(p.tag)-1);
                write(nm_sock,&h,sizeof(h)); write(nm_sock,&p,sizeof(p)); wait_for_response(nm_sock); close(nm_sock);
            }
        }
        else if (iequals(command, "listcheckpoints")) {
            char* filename = strtok(NULL, " ");
            if (!filename) { printf("Usage: listcheckpoints <filename>\n"); }
            else {
                int nm_sock = connect_to_server(nm_ip, nm_port); if (nm_sock==-1) continue;
                PacketHeader h; CheckpointListPayload p; h.type=MSG_LIST_CHECKPOINTS; h.size=sizeof(p); memset(&p,0,sizeof(p));
                strncpy(p.username, username, MAX_USERNAME_LEN); strncpy(p.filename, filename, MAX_PATH_LEN);
                write(nm_sock,&h,sizeof(h)); write(nm_sock,&p,sizeof(p));
                PacketHeader rh; ResponsePayload rp; if (read(nm_sock,&rh,sizeof(rh))>0 && read(nm_sock,&rp,rh.size)>0) {
                    if (rh.type==MSG_SUCCESS) printf("%s", rp.message); else printf("SERVER ERROR: %s\n", rp.message);
                } else { printf("SERVER ERROR: No response.\n"); }
                close(nm_sock);
            }
        }
        else if (iequals(command, "createfolder")) {
            char* folder = strtok(NULL, "");
            if (!folder) { printf("Usage: CREATEFOLDER <foldername>\n"); }
            else { handle_create_folder(folder); }
        }
        else if (iequals(command, "move")) {
            char* filename = strtok(NULL, " "); char* folder = strtok(NULL, "");
            if (!filename || !folder) { printf("Usage: MOVE <filename> <foldername>\n"); }
            else { handle_move_file(filename, folder); }
        }
        else if (iequals(command, "viewfolder")) {
            char* folder = strtok(NULL, "");
            if (!folder) { printf("Usage: VIEWFOLDER <foldername>\n"); }
            else { handle_view_folder(folder); }
        }
        else if (iequals(command, "deletefolder")) {
            char* folder = strtok(NULL, "");
            if (!folder) { printf("Usage: DELETEFOLDER <foldername>\n"); }
            else { handle_delete_folder(folder); }
        }
        else if (iequals(command, "addaccess")) {
            // Support both forms:
            //   addaccess -R <filename> <username>
            //   addaccess -W <filename> <username>
            //   addaccess <filename> <username> <R|W>   (legacy)
            char* t1 = strtok(NULL, " ");
            if (!t1) { printf("Usage: addaccess -R|-W <filename> <username>\n       or: addaccess <filename> <username> <R|W>\n"); }
            else if (strcmp(t1, "-R") == 0 || strcmp(t1, "-W") == 0) {
                char* filename = strtok(NULL, " ");
                char* target_user = strtok(NULL, " ");
                if (filename && target_user) {
                    const char* access = (strcmp(t1, "-W") == 0) ? "W" : "R";
                    handle_add_access(filename, target_user, access);
                } else {
                    printf("Usage: addaccess %s <filename> <username>\n", t1);
                }
            } else {
                // Legacy form
                char* filename = t1;
                char* target_user = strtok(NULL, " ");
                char* access = strtok(NULL, " ");
                if (filename && target_user && access) {
                    handle_add_access(filename, target_user, access);
                } else {
                    printf("Usage: addaccess -R|-W <filename> <username>\n       or: addaccess <filename> <username> <R|W>\n");
                }
            }
        } else if (iequals(command, "remaccess")) {
            char* filename = strtok(NULL, " ");
            char* target_user = strtok(NULL, " ");
            if (filename && target_user) {
                handle_rem_access(filename, target_user);
            } else {
                printf("Usage: remaccess <filename> <username>\n");
            }
        } else if (iequals(command, "undo")) {
            char* filename = strtok(NULL, " ");
            if (filename) {
                handle_undo(filename);
            } else {
                printf("Usage: undo <filename>\n");
            }
        } else if (iequals(command, "info")) {
            char* filename = strtok(NULL, " ");
            if (filename) {
                handle_info(filename);
            } else {
                printf("Usage: info <filename>\n");
            }
        } else if (iequals(command, "stream")) {
            char* filename = strtok(NULL, " ");
            if (filename) {
                handle_stream(filename);
            } else {
                printf("Usage: stream <filename>\n");
            }
        } else if (iequals(command, "list")) {
            handle_list();
        } else if (iequals(command, "resetusers")) {
            handle_reset_users();
        } else if (iequals(command, "exec")) {
            char* filename = strtok(NULL, " ");
            if (filename) {
                handle_exec(filename);
            } else {
                printf("Usage: exec <filename>\n");
            }
        } else if (iequals(command, "requestaccess")) {
            // requestaccess <filename> <R|W>
            char* filename = strtok(NULL, " ");
            char* type = strtok(NULL, " ");
            if (!filename || !type || !(iequals(type,"R")||iequals(type,"W"))) { printf("Usage: requestaccess <filename> <R|W>\n"); }
            else {
                int nm_sock = connect_to_server(nm_ip, nm_port); if (nm_sock==-1) continue;
                PacketHeader h; AccessRequestPayload p; h.type=MSG_REQUEST_ACCESS; h.size=sizeof(p); memset(&p,0,sizeof(p)); strncpy(p.requester_username, username, MAX_USERNAME_LEN); strncpy(p.filename, filename, MAX_PATH_LEN); p.requested_type = iequals(type,"W")?1:0; write(nm_sock,&h,sizeof(h)); write(nm_sock,&p,sizeof(p)); wait_for_response(nm_sock); close(nm_sock);
            }
        } else if (iequals(command, "listrequests")) {
            // listrequests <filename>
            char* filename = strtok(NULL, " ");
            if (!filename) { printf("Usage: listrequests <filename>\n"); }
            else {
                int nm_sock = connect_to_server(nm_ip, nm_port); if (nm_sock==-1) continue;
                PacketHeader h; AccessListQueryPayload q; h.type=MSG_LIST_ACCESS_REQUESTS; h.size=sizeof(q); memset(&q,0,sizeof(q)); strncpy(q.owner_username, username, MAX_USERNAME_LEN); strncpy(q.filename, filename, MAX_PATH_LEN); write(nm_sock,&h,sizeof(h)); write(nm_sock,&q,sizeof(q)); wait_for_response(nm_sock); close(nm_sock);
            }
        } else if (iequals(command, "approvereq")) {
            // approvereq <filename> <username>
            char* filename = strtok(NULL, " "); char* target = strtok(NULL, " ");
            if (!filename || !target) { printf("Usage: approvereq <filename> <username>\n"); }
            else {
                int nm_sock = connect_to_server(nm_ip, nm_port); if (nm_sock==-1) continue;
                PacketHeader h; AccessDecisionPayload d; h.type=MSG_DECIDE_ACCESS; h.size=sizeof(d); memset(&d,0,sizeof(d)); strncpy(d.owner_username, username, MAX_USERNAME_LEN); strncpy(d.target_username, target, MAX_USERNAME_LEN); strncpy(d.filename, filename, MAX_PATH_LEN); d.approve=1; write(nm_sock,&h,sizeof(h)); write(nm_sock,&d,sizeof(d)); wait_for_response(nm_sock); close(nm_sock);
            }
        } else if (iequals(command, "denyreq")) {
            // denyreq <filename> <username>
            char* filename = strtok(NULL, " "); char* target = strtok(NULL, " ");
            if (!filename || !target) { printf("Usage: denyreq <filename> <username>\n"); }
            else {
                int nm_sock = connect_to_server(nm_ip, nm_port); if (nm_sock==-1) continue;
                PacketHeader h; AccessDecisionPayload d; h.type=MSG_DECIDE_ACCESS; h.size=sizeof(d); memset(&d,0,sizeof(d)); strncpy(d.owner_username, username, MAX_USERNAME_LEN); strncpy(d.target_username, target, MAX_USERNAME_LEN); strncpy(d.filename, filename, MAX_PATH_LEN); d.approve=0; write(nm_sock,&h,sizeof(h)); write(nm_sock,&d,sizeof(d)); wait_for_response(nm_sock); close(nm_sock);
            }
        }
        // --- END NEW ---
        else if (strcmp(command, "exit") == 0) {
            break;
        } else {
            printf("Unknown command: %s\n", command);
        }
    }
    
    // Send disconnect message to Name Server before exiting
    int nm_sock = connect_to_server(nm_ip, nm_port);
    if (nm_sock != -1) {
        PacketHeader h;
        h.type = MSG_CLIENT_DISCONNECT;
        h.size = sizeof(ClientRegisterPayload);
        ClientRegisterPayload p;
        memset(&p, 0, sizeof(p));
        strncpy(p.username, username, MAX_USERNAME_LEN);
        write(nm_sock, &h, sizeof(h));
        write(nm_sock, &p, sizeof(p));
        // Wait for acknowledgment
        PacketHeader ack_h; ResponsePayload ack_p;
        if (read(nm_sock, &ack_h, sizeof(ack_h)) > 0 && read(nm_sock, &ack_p, ack_h.size) > 0) {
            // Silent acknowledgment received
        }
        close(nm_sock);
    }
    
    if (nm_disconnected) {
        printf("Client terminated due to Name Server disconnection.\n");
    } else if (interrupted) {
        printf("Shutdown complete. Bye!\n");
    } else {
        printf("Goodbye!\n");
    }
    return 0;
}