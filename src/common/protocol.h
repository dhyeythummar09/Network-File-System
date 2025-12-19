#ifndef PROTOCOL_H
#define PROTOCOL_H

#define NM_PORT 8080         // Publicly known port for the Name Server
#define MAX_PATH_LEN 256     // Max length for a file path/name
#define MAX_USERNAME_LEN 50  // Max length for a username
#define MAX_MSG_LEN 1024     // Max length for general messages/data
#define MAX_SERVERS 10       // Max number of storage servers
#define MAX_FILES 100        // Max number of files
#define MAX_USERS 50                 // Max number of users with explicit permissions per file (ACL size)
#define MAX_REGISTERED_USERS 200     // Max number of globally registered users (user registry capacity)
#define SS_IP "127.0.0.1"    // Placeholder IP for SS

// Enum to define different types of messages/commands
typedef enum {
    // Phase 1: Registration
    MSG_CLIENT_REGISTER,
    MSG_CLIENT_DISCONNECT,
    MSG_SS_REGISTER,
    
    // Phase 2: Client -> Name Server requests
    MSG_CREATE_FILE,    // "create <filename>"
    MSG_READ_FILE,      // "read <filename>"
    MSG_WRITE_FILE,     // "write <filename>"
    MSG_DELETE_FILE,    // "delete <filename>"

    // Phase 2: Name Server -> Storage Server requests
    MSG_SS_CREATE_FILE, // NM tells SS to create a file
    MSG_SS_DELETE_FILE, // NM tells SS to delete a file

    // Phase 2: Name Server -> Client responses
    MSG_REDIRECT_TO_SS, // NM tells client which SS to talk to
    MSG_SUCCESS,        // Generic success
    MSG_ERROR,          // Generic error

    // Phase 2: Client -> Storage Server requests
    MSG_SS_READ_FILE,   // Client asks SS for file content
    MSG_SS_WRITE_FILE,  // Client sends file content to SS

    // --- Phase 3: New Operations ---
    
    // Teammate's operations
    MSG_VIEW_FILES,     // Client -> NM (VIEW)
    MSG_INFO_FILE,      // Client -> NM (INFO)
    MSG_LIST_USERS,     // Client -> NM (LIST)
    MSG_STREAM_FILE,    // Client -> NM (STREAM)
    MSG_EXEC_FILE,      // Client -> NM (EXEC)

    // Your operations (Access Control)
    MSG_ADD_ACCESS,     // Client -> NM (ADDACCESS)
    MSG_REM_ACCESS,     // Client -> NM (REMACCESS)

    // Your operations (New Write & Undo)
    MSG_SS_WRITE_SENTENCE, // Client -> SS: Write a word to a sentence
    MSG_SS_ETIRW,          // Client -> SS: End write session, release lock
    MSG_SS_UNDO,           // Client -> NM -> SS: Undo last change
    MSG_SS_STREAM_FILE,    // Client -> SS: Stream file word-by-word
    MSG_SS_EXEC_FILE,      // Client -> SS: Execute file

    // Streaming sub-events (SS -> Client)
    MSG_STREAM_WORD,       // SS -> Client: One word chunk in a stream
    MSG_STREAM_END         // SS -> Client: End of stream marker

    // --- Bonus: Access Request Workflow ---
    ,MSG_REQUEST_ACCESS      // Client -> NM: Request access to a file
    ,MSG_LIST_ACCESS_REQUESTS// Client -> NM: Owner lists pending requests for a file
    ,MSG_DECIDE_ACCESS       // Client -> NM: Owner approves/denies a pending request
    ,MSG_LIST_OWNER_FILES    // Client -> NM: Owner lists own files with pending counts
    // --- Bonus: Checkpoints ---
    ,MSG_CHECKPOINT          // Client -> NM: Create checkpoint with tag
    ,MSG_VIEW_CHECKPOINT     // Client -> NM: View checkpoint content
    ,MSG_REVERT_CHECKPOINT   // Client -> NM: Revert to checkpoint
    ,MSG_LIST_CHECKPOINTS    // Client -> NM: List checkpoint tags

    // Storage Server operations for checkpoints
    ,MSG_SS_CHECKPOINT_CREATE
    ,MSG_SS_CHECKPOINT_VIEW
    ,MSG_SS_CHECKPOINT_REVERT
    ,MSG_SS_CHECKPOINT_LIST

    // --- Bonus: Folder Hierarchy ---
    ,MSG_CREATE_FOLDER        // Client -> NM: Create a folder (possibly nested)
    ,MSG_MOVE_FILE            // Client -> NM: Move file into a folder
    ,MSG_VIEW_FOLDER          // Client -> NM: List files under a folder (non-recursive)
    ,MSG_SS_CREATE_FOLDER     // NM -> SS: Ensure folder path exists
    ,MSG_SS_MOVE_FILE         // NM -> SS: Move file and related artifacts
    ,MSG_SS_VIEW_FOLDER       // NM -> SS: List files under a folder

    // Delete folder
    ,MSG_DELETE_FOLDER        // Client -> NM: Delete a folder recursively
    ,MSG_SS_DELETE_FOLDER     // NM -> SS: Delete a folder recursively

    // --- Administrative ---
    ,MSG_RESET_USERS          // Client -> NM: Reset all registered users and their files (admin only)

} MessageType;

// --- Generic Header ---
typedef struct {
    MessageType type;
    int size; // Size of the payload/data that follows this header
} PacketHeader;

// --- Phase 1 Payloads ---
typedef struct {
    char username[MAX_USERNAME_LEN];
    // Additional client context for logging/monitoring per spec
    char ip_addr[16];   // Client's IP (optional; NM may derive from socket)
    int nm_port;        // NM port used by client
    int ss_port;        // Reserved (clients typically don't listen; set 0)
} ClientRegisterPayload;

typedef struct {
    char ip_addr[16];
    int nm_port;           // NM port this SS connected to (for bookkeeping)
    int client_port;       // The port clients should use
    int num_files;         // Number of files reported on this SS
    char files_blob[MAX_MSG_LEN]; // Newline-separated list of filenames (e.g., *.txt)
} SSRegisterPayload;

// --- Phase 2 Payloads ---

// Generic request for a file
// MODIFIED: Added username for access control
typedef struct {
    char username[MAX_USERNAME_LEN];
    char filename[MAX_PATH_LEN];
} FileRequestPayload;

// Folder related payloads
typedef struct {
    char username[MAX_USERNAME_LEN];
    char folder[MAX_PATH_LEN];
} FolderRequestPayload;

typedef struct {
    char username[MAX_USERNAME_LEN];
    char filename[MAX_PATH_LEN];
    char folder[MAX_PATH_LEN];
} MoveRequestPayload;

typedef struct {
    char username[MAX_USERNAME_LEN];
    char folder[MAX_PATH_LEN];
} ViewFolderPayload;

// Payload for NM -> Client redirect
typedef struct {
    char ip_addr[16];
    int port;
} SSRedirectPayload;

// Payload for Client -> SS write request
typedef struct {
    char filename[MAX_PATH_LEN];
    char content[MAX_MSG_LEN];
} SSWritePayload;

// Payload for SS -> Client read response
typedef struct {
    char content[MAX_MSG_LEN];
} SSReadPayload;

// Generic response payloads
typedef struct {
    char message[MAX_MSG_LEN];
} ResponsePayload;

// --- Phase 3 Payloads (NEW) ---

// Payload for Client -> SS sentence write request
typedef struct {
    char username[MAX_USERNAME_LEN];
    char filename[MAX_PATH_LEN];
    int sentence_number;
    int word_index;
    char content[MAX_MSG_LEN]; // Content to insert/overwrite
    int session_id;            // Unique client edit session id
} SSWriteSentencePayload;

// Payload for Client -> NM access control changes
typedef struct {
    char requestor_username[MAX_USERNAME_LEN]; // The user making the request (must be owner)
    char target_username[MAX_USERNAME_LEN];  // The user to add/remove
    char filename[MAX_PATH_LEN];
    int access_type; // For ADDACCESS: 0 for Read, 1 for Read/Write
} AccessPayload;

// --- Bonus: Access Request Payloads ---
typedef struct {
    char requester_username[MAX_USERNAME_LEN]; // User requesting access
    char filename[MAX_PATH_LEN];
    int requested_type; // 0 -> Read, 1 -> Read/Write
} AccessRequestPayload;

typedef struct {
    char owner_username[MAX_USERNAME_LEN]; // Owner issuing decision
    char target_username[MAX_USERNAME_LEN]; // Requesting user
    char filename[MAX_PATH_LEN];
    int approve; // 1 approve, 0 deny
} AccessDecisionPayload;

typedef struct {
    char owner_username[MAX_USERNAME_LEN];
    char filename[MAX_PATH_LEN];
} AccessListQueryPayload;

// Owner files overview (list files owned by user, with pending counts)
typedef struct {
    char owner_username[MAX_USERNAME_LEN];
} OwnerFilesQueryPayload;

// Simple payload for requests that just need user and file context
// Used for: ETIRW, UNDO
typedef struct {
    char username[MAX_USERNAME_LEN];
    char filename[MAX_PATH_LEN];
} SimpleFileUserPayload;

// --- New: VIEW request payload ---
// list_all: 0 -> only files user has access to; 1 -> all files in system
// with_details: 0 -> names only; 1 -> include details
typedef struct {
    char username[MAX_USERNAME_LEN];
    int list_all;
    int with_details;
} ViewRequestPayload;

// --- New: For sentence editing end/undo, include sentence_number ---
typedef struct {
    char username[MAX_USERNAME_LEN];
    char filename[MAX_PATH_LEN];
    int sentence_number; // 0-based index of sentence being edited
    int session_id;      // Bind ETIRW/UNDO to the same client session
} SimpleFileUserSentencePayload;

// --- Checkpoint payloads ---
typedef struct {
    char username[MAX_USERNAME_LEN];
    char filename[MAX_PATH_LEN];
    char tag[64];
} CheckpointTagPayload;

typedef struct {
    char username[MAX_USERNAME_LEN];
    char filename[MAX_PATH_LEN];
} CheckpointListPayload;


#endif // PROTOCOL_H