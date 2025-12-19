#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include <errno.h>
#include <sys/wait.h>
#include <stdarg.h>
#include "../common/protocol.h"
#include "../common/network.h"
#include "../common/logger.h"

// --- Internal state ---
typedef struct {
    char username[MAX_USERNAME_LEN];
    int has_write_access; // 1 for RW, 0 for R-only
} AccessEntry;

typedef struct {
    char filename[MAX_PATH_LEN];
    int server_index;
    char owner_username[MAX_USERNAME_LEN];
    AccessEntry acl[MAX_USERS];
    int num_acl_entries;
    time_t created_time;
    time_t modified_time;
    time_t last_access;
    // Bonus: Pending access requests
    char pending_req_user[MAX_USERS][MAX_USERNAME_LEN];
    int pending_req_type[MAX_USERS]; // 0 read, 1 write
    int num_pending_requests;
} FileIndexEntry;

static SSRegisterPayload active_servers[MAX_SERVERS];
static int server_alive[MAX_SERVERS]; // Heartbeat status: 1 alive, 0 down
static int num_servers = 0;
static FileIndexEntry file_index[MAX_FILES];
static int num_files = 0;
// Registry of globally registered usernames (distinct from per-file ACL capacity)
static char registered_users[MAX_REGISTERED_USERS][MAX_USERNAME_LEN];
static int num_users = 0;
static pthread_mutex_t file_system_mutex = PTHREAD_MUTEX_INITIALIZER;

// Persistence file paths
#define FILE_INDEX_PATH "nm_file_index.dat"
#define USER_REGISTRY_PATH "nm_user_registry.dat"
#define FOLDER_REGISTRY_PATH "nm_folders.dat"
#define FILE_INDEX_MAGIC 0x4E4D4649 /* 'NMFI' */
#define FILE_INDEX_VERSION 2

// Folder registry (tracks user-created folders)
#define MAX_FOLDERS 2048
static char created_folders[MAX_FOLDERS][MAX_PATH_LEN];
static int num_folders = 0;

// --- Hash Table for Efficient File Lookup ---
#define HASH_TABLE_SIZE 211  // Prime number for better distribution
typedef struct HashNode {
    char filename[MAX_PATH_LEN];
    int file_index;  // Index in file_index array
    struct HashNode* next;
} HashNode;

static HashNode* file_hash_table[HASH_TABLE_SIZE];

// Simple hash function (djb2)
static unsigned int hash_filename(const char* str) {
    unsigned long hash = 5381;
    int c;
    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c; // hash * 33 + c
    }
    return hash % HASH_TABLE_SIZE;
}

// Add file to hash table
static void hash_add_file(const char* filename, int index) {
    unsigned int bucket = hash_filename(filename);
    HashNode* node = malloc(sizeof(HashNode));
    if (!node) return;
    strncpy(node->filename, filename, MAX_PATH_LEN);
    node->file_index = index;
    node->next = file_hash_table[bucket];
    file_hash_table[bucket] = node;
}

// Remove file from hash table
static void hash_remove_file(const char* filename) {
    unsigned int bucket = hash_filename(filename);
    HashNode** ptr = &file_hash_table[bucket];
    while (*ptr) {
        if (strcmp((*ptr)->filename, filename) == 0) {
            HashNode* to_free = *ptr;
            *ptr = (*ptr)->next;
            free(to_free);
            return;
        }
        ptr = &(*ptr)->next;
    }
}

// Find file in hash table (O(1) average case)
static int hash_find_file(const char* filename) {
    unsigned int bucket = hash_filename(filename);
    HashNode* node = file_hash_table[bucket];
    while (node) {
        if (strcmp(node->filename, filename) == 0) {
            return node->file_index;
        }
        node = node->next;
    }
    return -1;
}

// Rebuild hash table (called after loading from disk)
static void hash_rebuild() {
    // Also clear LRU cache as indices may shift after rebuild
    extern void lru_clear(void); // forward declaration
    lru_clear();
    // Clear existing hash table
    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        HashNode* node = file_hash_table[i];
        while (node) {
            HashNode* next = node->next;
            free(node);
            node = next;
        }
        file_hash_table[i] = NULL;
    }
    // Rebuild from file_index
    for (int i = 0; i < num_files; i++) {
        hash_add_file(file_index[i].filename, i);
    }
    LOG_INFO("Hash table rebuilt with %d files", num_files);
}

// --- Small LRU Cache for recent file lookups ---
#define LRU_CAPACITY 32
typedef struct {
    char filename[MAX_PATH_LEN];
    int index; // index in file_index array
    int in_use;
} LRUEntry;
static LRUEntry lru[LRU_CAPACITY];
static int lru_count = 0;

static void lru_init(void) { lru_count = 0; for (int i=0;i<LRU_CAPACITY;i++){ lru[i].in_use=0; lru[i].filename[0]='\0'; lru[i].index=-1; } }
void lru_clear(void) { lru_init(); }
static int lru_get(const char* filename) {
    for (int i=0;i<lru_count;i++) {
        if (lru[i].in_use && strcmp(lru[i].filename, filename)==0) {
            // Move-to-front
            LRUEntry hit = lru[i];
            for (int j=i;j>0;j--) lru[j]=lru[j-1];
            lru[0]=hit;
            return hit.index;
        }
    }
    return -1;
}
static void lru_put(const char* filename, int idx) {
    // Remove existing if present
    int pos=-1; for (int i=0;i<lru_count;i++) if (lru[i].in_use && strcmp(lru[i].filename, filename)==0) { pos=i; break; }
    if (pos>=0) { for (int j=pos;j>0;j--) lru[j]=lru[j-1]; strncpy(lru[0].filename, filename, MAX_PATH_LEN); lru[0].index=idx; lru[0].in_use=1; return; }
    // Insert at front, evict last if full
    if (lru_count < LRU_CAPACITY) lru_count++;
    for (int j=lru_count-1;j>0;j--) lru[j]=lru[j-1];
    strncpy(lru[0].filename, filename, MAX_PATH_LEN); lru[0].filename[MAX_PATH_LEN-1]='\0'; lru[0].index=idx; lru[0].in_use=1;
}
static void lru_remove(const char* filename) {
    for (int i=0;i<lru_count;i++) {
        if (lru[i].in_use && strcmp(lru[i].filename, filename)==0) {
            for (int j=i;j<lru_count-1;j++) lru[j]=lru[j+1];
            lru_count--; if (lru_count<0) lru_count=0; return;
        }
    }
}

// Initialize LRU at startup (static initialization OK)
__attribute__((constructor)) static void lru_ctor(void) { lru_init(); }

// --- Request logging with peer metadata ---
static void nm_log_request(int client_sock, const char* username, const char* fmt, ...) {
    char ip[64] = "?"; int port = 0; get_peer_address(client_sock, ip, sizeof(ip), &port);
    char msg[512]; va_list ap; va_start(ap, fmt); vsnprintf(msg, sizeof(msg), fmt, ap); va_end(ap);
    LOG_INFO("[%s:%d user:%s] %s", ip, port, (username && username[0])?username:"-", msg);
}

// --- Helpers ---
static int find_file_unsafe(const char* filename) {
    // Check small LRU first, then fallback to hash table
    int idx = lru_get(filename);
    if (idx != -1) return idx;
    idx = hash_find_file(filename);
    if (idx != -1) lru_put(filename, idx);
    return idx;
}

static int find_user_unsafe(const char* username) {
    for (int i = 0; i < num_users; i++) {
        if (strcmp(registered_users[i], username) == 0) return i;
    }
    return -1;
}

static int register_user_unsafe(const char* username) {
    if (find_user_unsafe(username) != -1) return 1; // Already exists
    if (num_users >= MAX_REGISTERED_USERS) return -1; // Registry full
    strncpy(registered_users[num_users], username, MAX_USERNAME_LEN);
    num_users++;
    return 0;
}

static int check_permission(const char* username, int file_idx, int is_write_op) {
    FileIndexEntry* file = &file_index[file_idx];
    // Admin override: 'system' user has full read/write/delete rights
    if (username && strcmp(username, "system") == 0) return 1;
    // Import rule: files owned by 'system' are readable by anyone, but not writable
    if (!is_write_op && strcmp(file->owner_username, "system") == 0) return 1;
    if (strcmp(username, file->owner_username) == 0) return 1;
    for (int i = 0; i < file->num_acl_entries; i++) {
        if (strcmp(username, file->acl[i].username) == 0) {
            if (is_write_op) return file->acl[i].has_write_access ? 1 : 0;
            return 1;
        }
    }
    return 0;
}

static void count_words_chars(const char* buf, int* out_words, int* out_chars) {
    int words = 0, chars = 0, in_word = 0;
    for (const char* p = buf; *p; ++p) {
        unsigned char c = (unsigned char)*p;
        if (c != '\n' && c != '\r') chars++;
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
            in_word = 0;
        } else if (!in_word) { words++; in_word = 1; }
    }
    if (out_words) *out_words = words;
    if (out_chars) *out_chars = chars;
}

static int fetch_file_and_stats(const SSRegisterPayload* ss, const char* username, const char* filename,
                         int* out_words, int* out_chars) {
    int ss_sock = tcp_connect(ss->ip_addr, ss->client_port);
    if (ss_sock == -1) return -1;
    PacketHeader hdr; FileRequestPayload req;
    hdr.type = MSG_SS_READ_FILE; hdr.size = sizeof(req);
    memset(&req, 0, sizeof(req));
    strncpy(req.username, username, MAX_USERNAME_LEN);
    strncpy(req.filename, filename, MAX_PATH_LEN);
    write_all(ss_sock, &hdr, sizeof(hdr));
    write_all(ss_sock, &req, sizeof(req));
    PacketHeader res_h; SSReadPayload res_p;
    if (read_all(ss_sock, &res_h, sizeof(res_h)) == -1) { close(ss_sock); return -1; }
    if (res_h.size > (int)sizeof(res_p)) res_h.size = sizeof(res_p);
    if (read_all(ss_sock, &res_p, res_h.size) == -1) { close(ss_sock); return -1; }
    close(ss_sock);
    if (res_h.type != MSG_SUCCESS) return -1;
    count_words_chars(res_p.content, out_words, out_chars);
    return 0;
}

// --- Persistence Functions ---
static void save_file_index() {
    FILE* fp = fopen(FILE_INDEX_PATH, "wb");
    if (!fp) {
        LOG_ERROR("Failed to save file index: %s", strerror(errno));
        return;
    }
    /* Write magic + version for forward compatibility */
    unsigned int magic = FILE_INDEX_MAGIC; int version = FILE_INDEX_VERSION;
    fwrite(&magic, sizeof(magic), 1, fp);
    fwrite(&version, sizeof(version), 1, fp);
    fwrite(&num_files, sizeof(int), 1, fp);
    fwrite(file_index, sizeof(FileIndexEntry), num_files, fp);
    fclose(fp);
    LOG_INFO("Persistence: Saved %d files (v%d) to %s", num_files, version, FILE_INDEX_PATH);
}

/* Legacy (version 1) structure without pending request fields */
typedef struct LegacyFileIndexEntry {
    char filename[MAX_PATH_LEN];
    int server_index;
    char owner_username[MAX_USERNAME_LEN];
    AccessEntry acl[MAX_USERS];
    int num_acl_entries;
    time_t created_time;
    time_t modified_time;
    time_t last_access;
} LegacyFileIndexEntry;

static void migrate_legacy_entry(const LegacyFileIndexEntry* old, FileIndexEntry* neo) {
    memset(neo, 0, sizeof(*neo));
    strncpy(neo->filename, old->filename, MAX_PATH_LEN);
    neo->server_index = old->server_index;
    strncpy(neo->owner_username, old->owner_username, MAX_USERNAME_LEN);
    memcpy(neo->acl, old->acl, sizeof(old->acl));
    neo->num_acl_entries = old->num_acl_entries;
    neo->created_time = old->created_time;
    neo->modified_time = old->modified_time;
    neo->last_access = old->last_access;
    neo->num_pending_requests = 0; /* none in legacy */
}

static void load_file_index() {
    FILE* fp = fopen(FILE_INDEX_PATH, "rb");
    if (!fp) {
        LOG_INFO("Persistence: No existing file index found, starting fresh");
        return;
    }
    /* Peek magic */
    unsigned int magic = 0; int version = 0; int read_magic = 0;
    size_t r = fread(&magic, sizeof(magic), 1, fp);
    if (r == 1 && magic == FILE_INDEX_MAGIC) {
        read_magic = 1;
        if (fread(&version, sizeof(version), 1, fp) != 1) { LOG_ERROR("Persistence: Corrupt index (version)." ); fclose(fp); return; }
        if (fread(&num_files, sizeof(int), 1, fp) != 1) { LOG_ERROR("Persistence: Corrupt index (count)." ); fclose(fp); return; }
        if (num_files < 0 || num_files > MAX_FILES) { LOG_ERROR("Persistence: Invalid file count %d", num_files); num_files=0; fclose(fp); return; }
        if (version == FILE_INDEX_VERSION) {
            size_t need = (size_t)num_files * sizeof(FileIndexEntry);
            if (need > 0) {
                if (fread(file_index, sizeof(FileIndexEntry), num_files, fp) != (size_t)num_files) {
                    LOG_ERROR("Persistence: Truncated index file."); num_files=0; fclose(fp); return; }
            }
            LOG_INFO("Persistence: Loaded %d files (v%d) from %s", num_files, version, FILE_INDEX_PATH);
        } else if (version == 1) {
            /* Migrate legacy entries */
            LegacyFileIndexEntry* legacy = malloc(num_files * sizeof(LegacyFileIndexEntry));
            if (!legacy) { LOG_ERROR("Persistence: OOM while migrating."); num_files=0; fclose(fp); return; }
            if (fread(legacy, sizeof(LegacyFileIndexEntry), num_files, fp) != (size_t)num_files) { LOG_ERROR("Persistence: Truncated legacy index."); free(legacy); num_files=0; fclose(fp); return; }
            for (int i=0;i<num_files;i++) migrate_legacy_entry(&legacy[i], &file_index[i]);
            free(legacy);
            LOG_INFO("Persistence: Migrated %d legacy (v1) files to v%d", num_files, FILE_INDEX_VERSION);
            /* Immediately resave in new format */
            fclose(fp); save_file_index(); return; /* save reopens file */
        } else {
            LOG_ERROR("Persistence: Unsupported index version %d", version); num_files=0; fclose(fp); return;
        }
    } else {
        /* Legacy file without magic: rewind and treat as version 1 raw */
        rewind(fp);
        if (fread(&num_files, sizeof(int), 1, fp) != 1) { LOG_ERROR("Persistence: Corrupt legacy index"); num_files=0; fclose(fp); return; }
        if (num_files < 0 || num_files > MAX_FILES) { LOG_ERROR("Persistence: Invalid legacy file count %d", num_files); num_files=0; fclose(fp); return; }
        LegacyFileIndexEntry* legacy = malloc(num_files * sizeof(LegacyFileIndexEntry));
        if (!legacy) { LOG_ERROR("Persistence: OOM legacy read"); num_files=0; fclose(fp); return; }
        if (fread(legacy, sizeof(LegacyFileIndexEntry), num_files, fp) != (size_t)num_files) { LOG_ERROR("Persistence: Truncated legacy entries"); free(legacy); num_files=0; fclose(fp); return; }
        for (int i=0;i<num_files;i++) migrate_legacy_entry(&legacy[i], &file_index[i]);
        free(legacy);
        fclose(fp);
        LOG_INFO("Persistence: Loaded and migrated %d legacy files (no magic)");
        save_file_index(); /* rewrite in new format */
        return;
    }
    fclose(fp);
}

static void save_user_registry() {
    FILE* fp = fopen(USER_REGISTRY_PATH, "wb");
    if (!fp) {
        LOG_ERROR("Failed to save user registry: %s", strerror(errno));
        return;
    }
    fwrite(&num_users, sizeof(int), 1, fp);
    fwrite(registered_users, sizeof(char[MAX_USERNAME_LEN]), num_users, fp);
    fclose(fp);
    LOG_INFO("Persistence: Saved %d users to %s", num_users, USER_REGISTRY_PATH);
}

static void load_user_registry() {
    FILE* fp = fopen(USER_REGISTRY_PATH, "rb");
    if (!fp) {
        LOG_INFO("Persistence: No existing user registry found, starting fresh");
        return;
    }
    if (fread(&num_users, sizeof(int), 1, fp) == 1) {
    if (num_users > 0 && num_users <= MAX_REGISTERED_USERS) {
            // Cap read to array size in case file contains more than current compiled limit
            if (num_users > MAX_REGISTERED_USERS) {
                LOG_WARN("User registry file lists %d users exceeding compiled MAX_REGISTERED_USERS=%d; truncating.", num_users, MAX_REGISTERED_USERS);
                num_users = MAX_REGISTERED_USERS;
            }
            fread(registered_users, sizeof(char[MAX_USERNAME_LEN]), num_users, fp);
            LOG_INFO("Persistence: Loaded %d users from %s", num_users, USER_REGISTRY_PATH);
        }
    }
    fclose(fp);
}

// --- Folder Registry Persistence ---
static void normalize_folder_path(const char* in, char* out, size_t n) {
    if (!in || !out || n==0) return;
    strncpy(out, in, n);
    out[n-1] = '\0';
    size_t L = strlen(out);
    while (L>0 && out[L-1] == '/') { out[L-1] = '\0'; L--; }
}

static int folder_index_of(const char* norm) {
    for (int i=0; i<num_folders; i++) {
        if (strcmp(created_folders[i], norm)==0) return i;
    }
    return -1;
}

static void save_folder_registry() {
    FILE* fp = fopen(FOLDER_REGISTRY_PATH, "wb");
    if (!fp) { LOG_ERROR("Failed to save folder registry: %s", strerror(errno)); return; }
    fwrite(&num_folders, sizeof(int), 1, fp);
    if (num_folders>0) fwrite(created_folders, sizeof(created_folders[0]), num_folders, fp);
    fclose(fp);
    LOG_INFO("Persistence: Saved %d folders to %s", num_folders, FOLDER_REGISTRY_PATH);
}

static void load_folder_registry() {
    FILE* fp = fopen(FOLDER_REGISTRY_PATH, "rb");
    if (!fp) { LOG_INFO("Persistence: No existing folder registry found, starting fresh"); return; }
    if (fread(&num_folders, sizeof(int), 1, fp) == 1) {
        if (num_folders >= 0 && num_folders <= MAX_FOLDERS) {
            if (num_folders>0) fread(created_folders, sizeof(created_folders[0]), num_folders, fp);
            LOG_INFO("Persistence: Loaded %d folders from %s", num_folders, FOLDER_REGISTRY_PATH);
        } else { num_folders = 0; }
    }
    fclose(fp);
}

static void add_user_folder(const char* folder) {
    char norm[MAX_PATH_LEN]; normalize_folder_path(folder, norm, sizeof(norm));
    if (norm[0]=='\0' || strcmp(norm, ".")==0 || strcmp(norm, "/")==0) return;
    if (folder_index_of(norm) != -1) return;
    if (num_folders < MAX_FOLDERS) {
        strncpy(created_folders[num_folders], norm, MAX_PATH_LEN);
        num_folders++;
        save_folder_registry();
    }
}

static void remove_user_folder_recursive(const char* folder) {
    char norm[MAX_PATH_LEN]; normalize_folder_path(folder, norm, sizeof(norm));
    if (norm[0]=='\0') return;
    // Remove exact match and any subfolders with prefix norm+
    char prefix[MAX_PATH_LEN+2]; snprintf(prefix,sizeof(prefix),"%s/", norm);
    int w=0;
    for (int i=0;i<num_folders;i++) {
        if (strcmp(created_folders[i], norm)==0 || strncmp(created_folders[i], prefix, strlen(prefix))==0) {
            continue; // skip (i.e., delete)
        }
        if (w!=i) strncpy(created_folders[w], created_folders[i], MAX_PATH_LEN);
        w++;
    }
    if (w != num_folders) { num_folders = w; save_folder_registry(); }
}

// --- Public API ---
void nm_logic_init() {
    // Initialize hash table
    memset(file_hash_table, 0, sizeof(file_hash_table));
    
    load_file_index();
    load_user_registry();
    load_folder_registry();
    
    // Rebuild hash table from loaded files
    hash_rebuild();
    
    LOG_INFO("Name Server logic initialized with persistent data and hash table");
    for (int i=0;i<MAX_SERVERS;i++) server_alive[i]=1; // optimistic default
}

void nm_handle_ss_registration(int sock) {
    SSRegisterPayload payload; memset(&payload, 0, sizeof(payload));
    if (read_all(sock, &payload, sizeof(payload)) == -1) return;
    pthread_mutex_lock(&file_system_mutex);
    if (num_servers < MAX_SERVERS) {
    active_servers[num_servers] = payload;
    server_alive[num_servers] = 1; // mark alive immediately
        int ss_index = num_servers;
        num_servers++;
        LOG_INFO("REGISTRATION: Storage Server at %s:%d (nm_port=%d) connected. (Total: %d) Reported files=%d",
                 payload.ip_addr, payload.client_port, payload.nm_port, num_servers, payload.num_files);
        // Import any reported files that are not known yet
        if (payload.num_files > 0 && payload.files_blob[0] != '\0') {
            char blob[MAX_MSG_LEN]; strncpy(blob, payload.files_blob, sizeof(blob)); blob[sizeof(blob)-1] = '\0';
            char* saveptr = NULL; char* line = strtok_r(blob, "\n", &saveptr);
            while (line) {
                // Trim spaces
                while (*line==' '||*line=='\t') line++;
                if (*line) {
                    if (find_file_unsafe(line) == -1 && num_files < MAX_FILES) {
                        time_t now = time(NULL);
                        file_index[num_files].server_index = ss_index;
                        strncpy(file_index[num_files].filename, line, MAX_PATH_LEN);
                        strncpy(file_index[num_files].owner_username, "system", MAX_USERNAME_LEN);
                        file_index[num_files].num_acl_entries = 0;
                        file_index[num_files].created_time = now;
                        file_index[num_files].modified_time = now;
                        file_index[num_files].last_access = now;
                        hash_add_file(line, num_files);
                        num_files++;
                    }
                }
                line = strtok_r(NULL, "\n", &saveptr);
            }
            save_file_index();
        }
    }
    pthread_mutex_unlock(&file_system_mutex);
}

void nm_handle_create_file(int client_sock) {
    FileRequestPayload payload; memset(&payload, 0, sizeof(payload));
    if (read_all(client_sock, &payload, sizeof(payload)) == -1) return;
    pthread_mutex_lock(&file_system_mutex);
    if (num_servers == 0) { pthread_mutex_unlock(&file_system_mutex); send_response(client_sock, MSG_ERROR, "No Storage Servers available."); return; }
    if (find_file_unsafe(payload.filename) != -1) { pthread_mutex_unlock(&file_system_mutex); send_response(client_sock, MSG_ERROR, "File already exists."); return; }
    int target_ss_index = 0; SSRegisterPayload target_ss = active_servers[target_ss_index];
    pthread_mutex_unlock(&file_system_mutex);

    int ss_sock = tcp_connect(target_ss.ip_addr, target_ss.client_port);
    if (ss_sock == -1) { send_response(client_sock, MSG_ERROR, "Failed to contact Storage Server."); return; }
    PacketHeader ss_header = { .type = MSG_SS_CREATE_FILE, .size = sizeof(payload) };
    write_all(ss_sock, &ss_header, sizeof(ss_header));
    write_all(ss_sock, &payload, sizeof(payload));
    PacketHeader res_header; ResponsePayload res_payload;
    if (read_all(ss_sock, &res_header, sizeof(res_header)) == -1 || read_all(ss_sock, &res_payload, res_header.size) == -1) {
        close(ss_sock); send_response(client_sock, MSG_ERROR, "No response from Storage Server."); return; }
    close(ss_sock);
    if (res_header.type == MSG_SUCCESS) {
        pthread_mutex_lock(&file_system_mutex);
        if (find_file_unsafe(payload.filename) == -1) {
            time_t now = time(NULL);
            int insert_idx = num_files;
            file_index[insert_idx].server_index = target_ss_index;
            strncpy(file_index[insert_idx].filename, payload.filename, MAX_PATH_LEN);
            strncpy(file_index[insert_idx].owner_username, payload.username, MAX_USERNAME_LEN);
            file_index[insert_idx].num_acl_entries = 0;
            file_index[insert_idx].created_time = now;
            file_index[insert_idx].modified_time = now;
            file_index[insert_idx].last_access = now;
            hash_add_file(payload.filename, insert_idx); // Add to hash table
            num_files++;
            save_file_index(); // Persist changes
            lru_put(payload.filename, insert_idx);
            send_response(client_sock, MSG_SUCCESS, "File created successfully.");
            nm_log_request(client_sock, payload.username, "Created file '%s' on SS %d", payload.filename, target_ss_index);
        } else {
            send_response(client_sock, MSG_ERROR, "File was created by another user just now.");
        }
        pthread_mutex_unlock(&file_system_mutex);
    } else {
        send_response(client_sock, MSG_ERROR, res_payload.message);
    }
}

void nm_handle_file_redirect(int client_sock, MessageType type) {
    FileRequestPayload payload; memset(&payload, 0, sizeof(payload));
    if (read_all(client_sock, &payload, sizeof(payload)) == -1) return;
    pthread_mutex_lock(&file_system_mutex);
    int file_idx = find_file_unsafe(payload.filename);
    if (file_idx == -1) { pthread_mutex_unlock(&file_system_mutex); send_response(client_sock, MSG_ERROR, "File not found."); return; }
    int is_write = (type == MSG_WRITE_FILE);
    if (!check_permission(payload.username, file_idx, is_write)) { pthread_mutex_unlock(&file_system_mutex); send_response(client_sock, MSG_ERROR, "Access Denied."); return; }
    file_index[file_idx].last_access = time(NULL);
    int ss_index = file_index[file_idx].server_index;
    if (ss_index < 0 || ss_index >= num_servers || server_alive[ss_index] == 0) {
        pthread_mutex_unlock(&file_system_mutex);
        send_response(client_sock, MSG_ERROR, "503 Storage Server unavailable.");
        return;
    }
    SSRegisterPayload target_ss = active_servers[ss_index];
    pthread_mutex_unlock(&file_system_mutex);

    PacketHeader res_header; SSRedirectPayload res_payload;
    res_header.type = MSG_REDIRECT_TO_SS; res_header.size = sizeof(res_payload);
    strncpy(res_payload.ip_addr, target_ss.ip_addr, 16); res_payload.port = target_ss.client_port;
    write_all(client_sock, &res_header, sizeof(res_header));
    write_all(client_sock, &res_payload, sizeof(res_payload));
    nm_log_request(client_sock, payload.username, "Redirecting for file '%s' to SS (%s:%d)", payload.filename, target_ss.ip_addr, target_ss.client_port);
}

void nm_handle_delete_file(int client_sock) {
    FileRequestPayload payload; memset(&payload, 0, sizeof(payload));
    if (read_all(client_sock, &payload, sizeof(payload)) == -1) return;
    pthread_mutex_lock(&file_system_mutex);
    int file_idx = find_file_unsafe(payload.filename);
    if (file_idx == -1) { pthread_mutex_unlock(&file_system_mutex); send_response(client_sock, MSG_ERROR, "File not found."); return; }
    // Allow admin 'system' to delete any file
    if (!(strcmp(payload.username, "system") == 0 || strcmp(payload.username, file_index[file_idx].owner_username) == 0)) {
        pthread_mutex_unlock(&file_system_mutex); send_response(client_sock, MSG_ERROR, "Access Denied: Only the owner or system can delete this file."); return; }
    SSRegisterPayload target_ss = active_servers[file_index[file_idx].server_index];
    pthread_mutex_unlock(&file_system_mutex);

    int ss_sock = tcp_connect(target_ss.ip_addr, target_ss.client_port);
    if (ss_sock == -1) { send_response(client_sock, MSG_ERROR, "Failed to contact Storage Server."); return; }
    PacketHeader ss_header = { .type = MSG_SS_DELETE_FILE, .size = sizeof(payload) };
    write_all(ss_sock, &ss_header, sizeof(ss_header));
    write_all(ss_sock, &payload, sizeof(payload));
    PacketHeader res_header; ResponsePayload res_payload;
    if (read_all(ss_sock, &res_header, sizeof(res_header)) == -1 || read_all(ss_sock, &res_payload, res_header.size) == -1) {
        close(ss_sock); send_response(client_sock, MSG_ERROR, "No response from Storage Server."); return; }
    close(ss_sock);
    if (res_header.type == MSG_SUCCESS) {
        pthread_mutex_lock(&file_system_mutex);
        int idx = find_file_unsafe(payload.filename);
        if (idx != -1) {
            hash_remove_file(payload.filename); // Remove from hash table
            for (int i = idx; i < num_files - 1; i++) file_index[i] = file_index[i + 1];
            num_files--;
            hash_rebuild(); // Rebuild hash table after shifting indices (also clears LRU)
            save_file_index(); // Persist changes
            send_response(client_sock, MSG_SUCCESS, "File deleted successfully.");
        } else {
            send_response(client_sock, MSG_ERROR, "File was already deleted by another user.");
        }
        pthread_mutex_unlock(&file_system_mutex);
    } else {
        send_response(client_sock, MSG_ERROR, res_payload.message);
    }
}

// --- Folder hierarchy ---
void nm_handle_create_folder(int client_sock) {
    FolderRequestPayload p; memset(&p,0,sizeof(p)); if (read_all(client_sock,&p,sizeof(p))==-1) return;
    pthread_mutex_lock(&file_system_mutex);
    if (num_servers == 0) { pthread_mutex_unlock(&file_system_mutex); send_response(client_sock, MSG_ERROR, "No Storage Servers available."); return; }
    SSRegisterPayload target_ss = active_servers[0];
    pthread_mutex_unlock(&file_system_mutex);
    int ss_sock = tcp_connect(target_ss.ip_addr, target_ss.client_port);
    if (ss_sock==-1) { send_response(client_sock, MSG_ERROR, "Failed to contact Storage Server."); return; }
    PacketHeader h={.type=MSG_SS_CREATE_FOLDER,.size=sizeof(p)}; write_all(ss_sock,&h,sizeof(h)); write_all(ss_sock,&p,sizeof(p));
    PacketHeader rh; ResponsePayload rp; if (read_all(ss_sock,&rh,sizeof(rh))==-1 || read_all(ss_sock,&rp,rh.size)==-1) { close(ss_sock); send_response(client_sock, MSG_ERROR, "No response from Storage Server."); return; }
    close(ss_sock);
    if (rh.type==MSG_SUCCESS) { add_user_folder(p.folder); }
    send_response(client_sock, rh.type, rp.message);
    nm_log_request(client_sock, p.username, "CREATEFOLDER '%s' -> %s", p.folder, rh.type==MSG_SUCCESS?"ok":"err");
}

void nm_handle_move_file(int client_sock) {
    MoveRequestPayload p; memset(&p,0,sizeof(p)); if (read_all(client_sock,&p,sizeof(p))==-1) return;
    pthread_mutex_lock(&file_system_mutex);
    int idx = find_file_unsafe(p.filename);
    if (idx==-1) { pthread_mutex_unlock(&file_system_mutex); send_response(client_sock, MSG_ERROR, "File not found."); return; }
    if (strcmp(file_index[idx].owner_username, p.username)!=0) { pthread_mutex_unlock(&file_system_mutex); send_response(client_sock, MSG_ERROR, "Only owner can move file."); return; }
    SSRegisterPayload target_ss = active_servers[file_index[idx].server_index];
    pthread_mutex_unlock(&file_system_mutex);
    int ss_sock = tcp_connect(target_ss.ip_addr, target_ss.client_port);
    if (ss_sock==-1) { send_response(client_sock, MSG_ERROR, "Failed to contact Storage Server."); return; }
    PacketHeader h={.type=MSG_SS_MOVE_FILE,.size=sizeof(p)}; write_all(ss_sock,&h,sizeof(h)); write_all(ss_sock,&p,sizeof(p));
    PacketHeader rh; ResponsePayload rp; if (read_all(ss_sock,&rh,sizeof(rh))==-1 || read_all(ss_sock,&rp,rh.size)==-1) { close(ss_sock); send_response(client_sock, MSG_ERROR, "No response from Storage Server."); return; }
    close(ss_sock);
    if (rh.type==MSG_SUCCESS) {
        pthread_mutex_lock(&file_system_mutex);
        // Build new full path as folder/basename
        char work[MAX_PATH_LEN]; strncpy(work, p.filename, sizeof(work)); work[sizeof(work)-1]='\0';
        const char* base = work; char* slash = strrchr(work,'/'); if (slash) base = slash+1;
        char newname[MAX_PATH_LEN]; if (p.folder[0]=='\0' || strcmp(p.folder,".")==0) snprintf(newname,sizeof(newname),"%s", base); else snprintf(newname,sizeof(newname),"%s/%s", p.folder, base);
        // Update index + hash
        char oldname[MAX_PATH_LEN]; strncpy(oldname, file_index[idx].filename, sizeof(oldname)); oldname[sizeof(oldname)-1]='\0';
        hash_remove_file(file_index[idx].filename);
        strncpy(file_index[idx].filename, newname, MAX_PATH_LEN);
        file_index[idx].modified_time = time(NULL);
        hash_add_file(file_index[idx].filename, idx);
        // Update LRU: remove old, add new
        lru_remove(oldname);
        lru_put(file_index[idx].filename, idx);
        save_file_index();
        pthread_mutex_unlock(&file_system_mutex);
    }
    send_response(client_sock, rh.type, rp.message);
    nm_log_request(client_sock, p.username, "MOVE '%s' -> '%s/' -> %s", p.filename, p.folder, rh.type==MSG_SUCCESS?"ok":"err");
}

void nm_handle_view_folder(int client_sock) {
    ViewFolderPayload p; memset(&p,0,sizeof(p)); if (read_all(client_sock,&p,sizeof(p))==-1) return;
    pthread_mutex_lock(&file_system_mutex);
    if (num_servers == 0) { pthread_mutex_unlock(&file_system_mutex); send_response(client_sock, MSG_ERROR, "No Storage Servers available."); return; }
    SSRegisterPayload target_ss = active_servers[0]; // Folder listing not tied to specific SS in this simple setup
    pthread_mutex_unlock(&file_system_mutex);
    int ss_sock = tcp_connect(target_ss.ip_addr, target_ss.client_port);
    if (ss_sock==-1) { send_response(client_sock, MSG_ERROR, "Failed to contact Storage Server."); return; }
    PacketHeader h={.type=MSG_SS_VIEW_FOLDER,.size=sizeof(p)}; write_all(ss_sock,&h,sizeof(h)); write_all(ss_sock,&p,sizeof(p));
    PacketHeader rh; ResponsePayload rp; if (read_all(ss_sock,&rh,sizeof(rh))==-1 || read_all(ss_sock,&rp,rh.size)==-1) { close(ss_sock); send_response(client_sock, MSG_ERROR, "No response from Storage Server."); return; }
    close(ss_sock);
    if (rh.type != MSG_SUCCESS) { send_response(client_sock, rh.type, rp.message); return; }
    // rp.message is newline-separated full paths in that folder; includes directories with trailing '/'
    char out[MAX_MSG_LEN]; out[0]='\0';
    pthread_mutex_lock(&file_system_mutex);
    char buf[MAX_MSG_LEN]; strncpy(buf, rp.message, sizeof(buf)); buf[sizeof(buf)-1]='\0';
    char* saveptr=NULL; char* line=strtok_r(buf, "\n", &saveptr);
    while (line) {
        size_t len = strlen(line);
        int is_dir = (len>0 && line[len-1]=='/');
        int idx = find_file_unsafe(line);
        if (is_dir) {
            // Show directory only if created by users or contains at least one visible file
            char norm[MAX_PATH_LEN]; strncpy(norm, line, sizeof(norm)); norm[sizeof(norm)-1]='\0';
            if (len>0 && norm[len-1]=='/') norm[len-1]='\0';
            int show = (folder_index_of(norm) != -1);
            if (!show) {
                char pref[MAX_PATH_LEN+2]; snprintf(pref,sizeof(pref),"%s/", norm);
                for (int i=0;i<num_files;i++) {
                    if (strncmp(file_index[i].filename, pref, strlen(pref))==0 && check_permission(p.username, i, 0)) { show=1; break; }
                }
            }
            if (show) {
                char ln[300]; snprintf(ln,sizeof(ln),"--> %s\n", line);
                if (strlen(out)+strlen(ln)+1 < sizeof(out)) strcat(out, ln);
            }
        } else if (idx>=0 && check_permission(p.username, idx, 0)) {
            char ln[300]; snprintf(ln,sizeof(ln),"--> %s\n", line);
            if (strlen(out)+strlen(ln)+1 < sizeof(out)) strcat(out, ln);
        }
        line = strtok_r(NULL, "\n", &saveptr);
    }
    pthread_mutex_unlock(&file_system_mutex);
    if (out[0]=='\0') strncpy(out, "(empty)\n", sizeof(out));
    send_response(client_sock, MSG_SUCCESS, out);
}

void nm_handle_delete_folder(int client_sock) {
    FolderRequestPayload p; memset(&p,0,sizeof(p)); if (read_all(client_sock,&p,sizeof(p))==-1) return;
    // Disallow deleting root
    if (p.folder[0]=='\0' || strcmp(p.folder, ".")==0 || strcmp(p.folder, "/")==0) { send_response(client_sock, MSG_ERROR, "Cannot delete root folder."); return; }
    // Normalize folder by stripping trailing '/'
    char folder[MAX_PATH_LEN]; strncpy(folder, p.folder, sizeof(folder)); folder[sizeof(folder)-1]='\0';
    size_t L = strlen(folder); while (L>0 && folder[L-1]=='/') { folder[L-1]='\0'; L--; }
    if (folder[0]=='\0') { send_response(client_sock, MSG_ERROR, "Invalid folder path."); return; }

    // Collect files under this folder and validate ownership
    pthread_mutex_lock(&file_system_mutex);
    int indices[MAX_FILES]; int count=0;
    char prefix[MAX_PATH_LEN+2]; snprintf(prefix,sizeof(prefix),"%s/", folder);
    for (int i=0;i<num_files;i++) {
        if (file_index[i].filename[0]=='\0') continue;
        if (strncmp(file_index[i].filename, prefix, strlen(prefix))==0) {
            // Require owner to be the requester
            if (strcmp(file_index[i].owner_username, p.username)!=0) {
                pthread_mutex_unlock(&file_system_mutex);
                char msg[256]; snprintf(msg,sizeof(msg),"Cannot delete: you do not own '%s'", file_index[i].filename);
                send_response(client_sock, MSG_ERROR, msg); return;
            }
            indices[count++]=i;
        }
    }
    if (count==0) {
        // No indexed files under this folder (either empty or all files owned by others but not indexed with ownership).
        // Allow deletion of an existing empty folder: forward best-effort to a storage server.
        if (num_servers > 0) {
            SSRegisterPayload target_ss = active_servers[0];
            pthread_mutex_unlock(&file_system_mutex);
            int ss_sock = tcp_connect(target_ss.ip_addr, target_ss.client_port);
            if (ss_sock != -1) {
                PacketHeader h = { .type = MSG_SS_DELETE_FOLDER, .size = sizeof(p) };
                write_all(ss_sock, &h, sizeof(h));
                write_all(ss_sock, &p, sizeof(p));
                PacketHeader rh; ResponsePayload rp;
                if (read_all(ss_sock, &rh, sizeof(rh)) != -1 && read_all(ss_sock, &rp, rh.size) != -1) {
                    // Ignore response content; treat success if SS responded with MSG_SUCCESS.
                }
                close(ss_sock);
            }
            send_response(client_sock, MSG_SUCCESS, "Folder deleted.");
        } else {
            pthread_mutex_unlock(&file_system_mutex);
            send_response(client_sock, MSG_ERROR, "No storage server available to delete folder.");
        }
        return;
    }

    // Delete files grouped by server
    int ok=1;
    for (int k=0;k<count;k++) {
        int i = indices[k];
        SSRegisterPayload target_ss = active_servers[file_index[i].server_index];
        FileRequestPayload fr; memset(&fr,0,sizeof(fr)); strncpy(fr.username, p.username, MAX_USERNAME_LEN); strncpy(fr.filename, file_index[i].filename, MAX_PATH_LEN);
        pthread_mutex_unlock(&file_system_mutex);
        int ss_sock = tcp_connect(target_ss.ip_addr, target_ss.client_port);
        if (ss_sock==-1) { ok=0; pthread_mutex_lock(&file_system_mutex); break; }
        PacketHeader h={.type=MSG_SS_DELETE_FILE,.size=sizeof(fr)}; write_all(ss_sock,&h,sizeof(h)); write_all(ss_sock,&fr,sizeof(fr));
        PacketHeader rh; ResponsePayload rp; if (read_all(ss_sock,&rh,sizeof(rh))==-1 || read_all(ss_sock,&rp,rh.size)==-1) { close(ss_sock); ok=0; pthread_mutex_lock(&file_system_mutex); break; }
        close(ss_sock);
        pthread_mutex_lock(&file_system_mutex);
        if (rh.type != MSG_SUCCESS) { ok=0; break; }
        // Remove from index
        int idx = find_file_unsafe(fr.filename);
        if (idx!=-1) {
            hash_remove_file(file_index[idx].filename);
            for (int j=idx;j<num_files-1;j++) file_index[j]=file_index[j+1];
            num_files--; hash_rebuild();
        }
    }
    // If all files removed, persist and ask SS to delete empty dirs
    if (ok) {
        save_file_index();
        // Ask a server to remove the directory tree (best-effort)
        if (num_servers>0) {
            SSRegisterPayload target_ss = active_servers[0];
            pthread_mutex_unlock(&file_system_mutex);
            int ss_sock = tcp_connect(target_ss.ip_addr, target_ss.client_port);
            if (ss_sock!=-1) {
                PacketHeader h={.type=MSG_SS_DELETE_FOLDER,.size=sizeof(p)}; write_all(ss_sock,&h,sizeof(h)); write_all(ss_sock,&p,sizeof(p));
                PacketHeader rh; ResponsePayload rp; if (read_all(ss_sock,&rh,sizeof(rh))!=-1 && read_all(ss_sock,&rp,rh.size)!=-1) {
                    // ignore content
                }
                close(ss_sock);
            }
            // Update folder registry
            pthread_mutex_lock(&file_system_mutex);
            remove_user_folder_recursive(folder);
            pthread_mutex_unlock(&file_system_mutex);
        } else {
            pthread_mutex_unlock(&file_system_mutex);
        }
        send_response(client_sock, MSG_SUCCESS, "Folder deleted.");
    } else {
        pthread_mutex_unlock(&file_system_mutex);
        send_response(client_sock, MSG_ERROR, "Failed to delete all files in folder.");
    }
}

void nm_handle_add_access(int client_sock) {
    AccessPayload payload; memset(&payload, 0, sizeof(payload));
    if (read_all(client_sock, &payload, sizeof(payload)) == -1) return;
    pthread_mutex_lock(&file_system_mutex);
    
    // Check if target user exists
    if (find_user_unsafe(payload.target_username) == -1) {
        pthread_mutex_unlock(&file_system_mutex);
        send_response(client_sock, MSG_ERROR, "Error: User not found in the system.");
        return;
    }
    
    int file_idx = find_file_unsafe(payload.filename);
    if (file_idx == -1) { pthread_mutex_unlock(&file_system_mutex); send_response(client_sock, MSG_ERROR, "File not found."); return; }
    FileIndexEntry* file = &file_index[file_idx];
    if (strcmp(payload.requestor_username, file->owner_username) != 0) { pthread_mutex_unlock(&file_system_mutex); send_response(client_sock, MSG_ERROR, "Access Denied: Only the owner can change permissions."); return; }
    
    // Don't allow adding owner to ACL (owner already has RW access)
    if (strcmp(payload.target_username, file->owner_username) == 0) {
        pthread_mutex_unlock(&file_system_mutex);
        send_response(client_sock, MSG_ERROR, "Owner already has full access. Cannot add owner to ACL.");
        return;
    }
    
    for (int i = 0; i < file->num_acl_entries; i++) {
        if (strcmp(file->acl[i].username, payload.target_username) == 0) {
            file->acl[i].has_write_access = payload.access_type;
            save_file_index(); // Persist changes
            pthread_mutex_unlock(&file_system_mutex);
            send_response(client_sock, MSG_SUCCESS, "Access updated successfully.");
            return;
        }
    }
    if (file->num_acl_entries >= MAX_USERS) { pthread_mutex_unlock(&file_system_mutex); send_response(client_sock, MSG_ERROR, "Access list is full."); return; }
    strncpy(file->acl[file->num_acl_entries].username, payload.target_username, MAX_USERNAME_LEN);
    file->acl[file->num_acl_entries].has_write_access = payload.access_type;
    file->num_acl_entries++;
    save_file_index(); // Persist changes
    pthread_mutex_unlock(&file_system_mutex);
    send_response(client_sock, MSG_SUCCESS, "Access granted successfully.");
}

void nm_handle_rem_access(int client_sock) {
    AccessPayload payload; memset(&payload, 0, sizeof(payload));
    if (read_all(client_sock, &payload, sizeof(payload)) == -1) return;
    pthread_mutex_lock(&file_system_mutex);
    int file_idx = find_file_unsafe(payload.filename);
    if (file_idx == -1) { pthread_mutex_unlock(&file_system_mutex); send_response(client_sock, MSG_ERROR, "File not found."); return; }
    FileIndexEntry* file = &file_index[file_idx];
    if (strcmp(payload.requestor_username, file->owner_username) != 0) { pthread_mutex_unlock(&file_system_mutex); send_response(client_sock, MSG_ERROR, "Access Denied: Only the owner can change permissions."); return; }
    int pos = -1; for (int i = 0; i < file->num_acl_entries; i++) if (strcmp(file->acl[i].username, payload.target_username) == 0) { pos = i; break; }
    if (pos == -1) { pthread_mutex_unlock(&file_system_mutex); send_response(client_sock, MSG_ERROR, "User not found in access list."); return; }
    for (int i = pos; i < file->num_acl_entries - 1; i++) file->acl[i] = file->acl[i + 1];
    file->num_acl_entries--;
    save_file_index(); // Persist changes
    pthread_mutex_unlock(&file_system_mutex);
    send_response(client_sock, MSG_SUCCESS, "Access removed successfully.");
}

void nm_handle_view_files(int client_sock) {
    ViewRequestPayload req; memset(&req, 0, sizeof(req));
    if (read_all(client_sock, &req, sizeof(req)) == -1) return;
    char out[MAX_MSG_LEN]; out[0] = '\0';
    pthread_mutex_lock(&file_system_mutex);
    // Gather indices of files to display, skipping empty filenames
    int indices[MAX_FILES]; int count = 0;
    for (int i = 0; i < num_files; i++) {
        if (file_index[i].filename[0] == '\0') continue; // skip blank entry
        int include = req.list_all ? 1 : check_permission(req.username, i, 0);
        if (!include) continue;
        indices[count++] = i;
    }
    // Simple alphabetical sort by filename (bubble for small N)
    for (int a = 0; a < count; a++) {
        for (int b = a + 1; b < count; b++) {
            if (strcasecmp(file_index[indices[a]].filename, file_index[indices[b]].filename) > 0) {
                int tmp = indices[a]; indices[a] = indices[b]; indices[b] = tmp;
            }
        }
    }
    // If not detailed: render with arrows
    if (!req.with_details) {
        for (int k = 0; k < count; k++) {
            int i = indices[k];
            char line[300]; snprintf(line, sizeof(line), "--> %s\n", file_index[i].filename);
            if (strlen(out) + strlen(line) + 1 < sizeof(out)) strcat(out, line);
        }
    } else {
        // Aesthetic numbered detailed view: one line per file
        // Format: 1) filename | owner = user | access = RW | words = N | chars = N | last_access = YYYY-MM-DD HH:MM:SS
        int digits = (count < 10) ? 1 : (count < 100 ? 2 : 3);
        for (int k = 0; k < count; k++) {
            int i = indices[k];
            int ss_idx = file_index[i].server_index; SSRegisterPayload ss = active_servers[ss_idx];
            char fname[MAX_PATH_LEN]; strncpy(fname, file_index[i].filename, sizeof(fname)); fname[sizeof(fname)-1]='\0';
            char owner[MAX_USERNAME_LEN]; strncpy(owner, file_index[i].owner_username, sizeof(owner)); owner[sizeof(owner)-1]='\0';
            int can_read = check_permission(req.username, i, 0);
            int can_write = check_permission(req.username, i, 1);
            const char* access = can_read ? (can_write ? "RW" : "R") : "-";
            pthread_mutex_unlock(&file_system_mutex);
            int words=-1, chars=-1; (void)fetch_file_and_stats(&ss, req.username, fname, &words, &chars);
            pthread_mutex_lock(&file_system_mutex);
            time_t last = file_index[i].last_access; char timebuf[32]; struct tm lt; localtime_r(&last,&lt); strftime(timebuf,sizeof(timebuf),"%Y-%m-%d %H:%M:%S", &lt);
            char line[600];
            snprintf(line, sizeof(line), "%*d) %s | owner = %s | access = %s | words = %d | chars = %d | last_access = %s\n",
                     digits, k+1, fname, owner, access, words, chars, timebuf);
            if (strlen(out) + strlen(line) + 1 < sizeof(out)) strcat(out, line);
        }
    }
    pthread_mutex_unlock(&file_system_mutex);
    if (out[0] == '\0') strncpy(out, "(no files)\n", sizeof(out));
    send_response(client_sock, MSG_SUCCESS, out);
}

void nm_handle_undo(int client_sock) {
    FileRequestPayload payload; 
    memset(&payload, 0, sizeof(payload));
    if (read_all(client_sock, &payload, sizeof(payload)) == -1) return;
    
    pthread_mutex_lock(&file_system_mutex);
    int file_idx = find_file_unsafe(payload.filename);
    if (file_idx == -1) { 
        pthread_mutex_unlock(&file_system_mutex); 
        send_response(client_sock, MSG_ERROR, "File not found."); 
        return; 
    }
    
    // Check if user has write permission (to undo changes)
    if (!check_permission(payload.username, file_idx, 1)) { 
        pthread_mutex_unlock(&file_system_mutex); 
        send_response(client_sock, MSG_ERROR, "Access Denied: You need write permission to undo."); 
        return; 
    }
    
    int ss_index = file_index[file_idx].server_index;
    if (ss_index < 0 || ss_index >= num_servers || server_alive[ss_index] == 0) {
        pthread_mutex_unlock(&file_system_mutex);
        send_response(client_sock, MSG_ERROR, "503 Storage Server unavailable.");
        return;
    }
    SSRegisterPayload target_ss = active_servers[ss_index];
    pthread_mutex_unlock(&file_system_mutex);
    
    // Forward undo request to storage server
    int ss_sock = tcp_connect(target_ss.ip_addr, target_ss.client_port);
    if (ss_sock == -1) { 
        send_response(client_sock, MSG_ERROR, "Failed to contact Storage Server."); 
        return; 
    }
    
    PacketHeader ss_header = { .type = MSG_SS_UNDO, .size = sizeof(payload) };
    write_all(ss_sock, &ss_header, sizeof(ss_header));
    write_all(ss_sock, &payload, sizeof(payload));
    
    // Read response from SS
    PacketHeader res_header; 
    ResponsePayload res_payload;
    if (read_all(ss_sock, &res_header, sizeof(res_header)) == -1 || 
        read_all(ss_sock, &res_payload, res_header.size) == -1) {
        close(ss_sock); 
        send_response(client_sock, MSG_ERROR, "No response from Storage Server."); 
        return; 
    }
    close(ss_sock);
    
    // Update modified time if successful
    if (res_header.type == MSG_SUCCESS) {
        pthread_mutex_lock(&file_system_mutex);
        file_idx = find_file_unsafe(payload.filename);
        if (file_idx != -1) {
            file_index[file_idx].modified_time = time(NULL);
        }
        pthread_mutex_unlock(&file_system_mutex);
    }
    
    // Forward SS response to client
    send_response(client_sock, res_header.type, res_payload.message);
    LOG_INFO("Request: Undo operation on '%s' - %s", payload.filename, 
             res_header.type == MSG_SUCCESS ? "Success" : "Failed");
}

void nm_handle_info(int client_sock) {
    FileRequestPayload payload; 
    memset(&payload, 0, sizeof(payload));
    if (read_all(client_sock, &payload, sizeof(payload)) == -1) return;
    
    pthread_mutex_lock(&file_system_mutex);
    int file_idx = find_file_unsafe(payload.filename);
    if (file_idx == -1) { 
        pthread_mutex_unlock(&file_system_mutex); 
        send_response(client_sock, MSG_ERROR, "File not found."); 
        return; 
    }
    
    // Check if user has at least read permission
    if (!check_permission(payload.username, file_idx, 0)) { 
        pthread_mutex_unlock(&file_system_mutex); 
        send_response(client_sock, MSG_ERROR, "Access Denied."); 
        return; 
    }
    
    // Update last access time since user is accessing file info
    file_index[file_idx].last_access = time(NULL);
    
    FileIndexEntry* file = &file_index[file_idx];
    int ss_index = file->server_index;
    if (ss_index < 0 || ss_index >= num_servers || server_alive[ss_index] == 0) {
        pthread_mutex_unlock(&file_system_mutex);
        send_response(client_sock, MSG_ERROR, "503 Storage Server unavailable.");
        return;
    }
    SSRegisterPayload target_ss = active_servers[ss_index];
    
    // Build info string
    char info[MAX_MSG_LEN];
    char created_str[64], modified_str[64], accessed_str[64];
    struct tm tm_buf;
    
    localtime_r(&file->created_time, &tm_buf);
    strftime(created_str, sizeof(created_str), "%Y-%m-%d %H:%M", &tm_buf);
    
    localtime_r(&file->modified_time, &tm_buf);
    strftime(modified_str, sizeof(modified_str), "%Y-%m-%d %H:%M", &tm_buf);
    
    localtime_r(&file->last_access, &tm_buf);
    strftime(accessed_str, sizeof(accessed_str), "%Y-%m-%d %H:%M", &tm_buf);
    
    // Get file size from SS
    int file_size = -1;
    pthread_mutex_unlock(&file_system_mutex);
    
    int ss_sock = tcp_connect(target_ss.ip_addr, target_ss.client_port);
    if (ss_sock != -1) {
        PacketHeader hdr; 
        FileRequestPayload req;
        hdr.type = MSG_SS_READ_FILE; 
        hdr.size = sizeof(req);
        memset(&req, 0, sizeof(req));
        strncpy(req.username, payload.username, MAX_USERNAME_LEN);
        strncpy(req.filename, payload.filename, MAX_PATH_LEN);
        write_all(ss_sock, &hdr, sizeof(hdr));
        write_all(ss_sock, &req, sizeof(req));
        
        PacketHeader res_h; 
        SSReadPayload res_p;
        if (read_all(ss_sock, &res_h, sizeof(res_h)) == 0 && res_h.type == MSG_SUCCESS) {
            if (read_all(ss_sock, &res_p, res_h.size) == 0) {
                file_size = strlen(res_p.content);
            }
        }
        close(ss_sock);
    }
    
    pthread_mutex_lock(&file_system_mutex);
    file_idx = find_file_unsafe(payload.filename); // Re-find in case it was deleted
    if (file_idx == -1) { 
        pthread_mutex_unlock(&file_system_mutex); 
        send_response(client_sock, MSG_ERROR, "File not found."); 
        return; 
    }
    file = &file_index[file_idx];
    
    // Build access list string
    char access_list[512] = "";
    char temp[128];
    snprintf(temp, sizeof(temp), "%s (RW)", file->owner_username);
    strcat(access_list, temp);
    
    for (int i = 0; i < file->num_acl_entries; i++) {
        snprintf(temp, sizeof(temp), ", %s (%s)", 
                 file->acl[i].username, 
                 file->acl[i].has_write_access ? "RW" : "R");
        if (strlen(access_list) + strlen(temp) < sizeof(access_list)) {
            strcat(access_list, temp);
        }
    }
    
    pthread_mutex_unlock(&file_system_mutex);
    
    // Format the info output
    snprintf(info, sizeof(info),
             "--> File: %s\n"
             "--> Owner: %s\n"
             "--> Created: %s\n"
             "--> Last Modified: %s\n"
             "--> Size: %d bytes\n"
             "--> Access: %s\n"
             "--> Last Accessed: %s by %s",
             payload.filename,
             file->owner_username,
             created_str,
             modified_str,
             file_size,
             access_list,
             accessed_str,
             payload.username);
    
    send_response(client_sock, MSG_SUCCESS, info);
    LOG_INFO("Request: Info for file '%s' requested by '%s'", payload.filename, payload.username);
}

void nm_handle_stream(int client_sock) {
    FileRequestPayload payload; 
    memset(&payload, 0, sizeof(payload));
    if (read_all(client_sock, &payload, sizeof(payload)) == -1) return;
    
    pthread_mutex_lock(&file_system_mutex);
    int file_idx = find_file_unsafe(payload.filename);
    if (file_idx == -1) { 
        pthread_mutex_unlock(&file_system_mutex); 
        send_response(client_sock, MSG_ERROR, "File not found."); 
        return; 
    }
    
    // Check if user has read permission
    if (!check_permission(payload.username, file_idx, 0)) { 
        pthread_mutex_unlock(&file_system_mutex); 
        send_response(client_sock, MSG_ERROR, "Access Denied."); 
        return; 
    }
    
    // Update last access time
    file_index[file_idx].last_access = time(NULL);
    
    int ss_index = file_index[file_idx].server_index;
    if (ss_index < 0 || ss_index >= num_servers || server_alive[ss_index] == 0) {
        pthread_mutex_unlock(&file_system_mutex);
        send_response(client_sock, MSG_ERROR, "503 Storage Server unavailable.");
        return;
    }
    SSRegisterPayload target_ss = active_servers[ss_index];
    pthread_mutex_unlock(&file_system_mutex);
    
    // Send redirect to client
    PacketHeader res_header; 
    SSRedirectPayload res_payload;
    res_header.type = MSG_REDIRECT_TO_SS; 
    res_header.size = sizeof(res_payload);
    strncpy(res_payload.ip_addr, target_ss.ip_addr, 16); 
    res_payload.port = target_ss.client_port;
    write_all(client_sock, &res_header, sizeof(res_header));
    write_all(client_sock, &res_payload, sizeof(res_payload));
    
    LOG_INFO("Request: Redirecting client for STREAM of file '%s' to SS (%s:%d)", 
             payload.filename, target_ss.ip_addr, target_ss.client_port);
}

void nm_register_user(const char* username, int client_sock) {
    pthread_mutex_lock(&file_system_mutex);
    int result = register_user_unsafe(username);
    if (result == 0) {
        save_user_registry(); // Persist new user
    }
    pthread_mutex_unlock(&file_system_mutex);
    
    // Send appropriate acknowledgment back to client
    PacketHeader response_header;
    ResponsePayload response;
    response_header.size = sizeof(response);
    if (result == 0) {
        response_header.type = MSG_SUCCESS;
        snprintf(response.message, sizeof(response.message), "User '%s' registered successfully", username);
    } else if (result == 1) {
        // Already existed in registry
        response_header.type = MSG_SUCCESS;
        snprintf(response.message, sizeof(response.message), "User '%s' already registered", username);
    } else { // result == -1 (full)
        response_header.type = MSG_ERROR;
        snprintf(response.message, sizeof(response.message), "User registry full (max %d users). Registration failed.", MAX_USERS);
    }
    write_all(client_sock, &response_header, sizeof(response_header));
    write_all(client_sock, &response, sizeof(response));
}

void nm_handle_list_users(int client_sock) {
    LOG_INFO("Request: LIST users");
    
    pthread_mutex_lock(&file_system_mutex);
    
    // Build response with all registered users
    char response[4096] = "Registered Users:\n";
    if (num_users == 0) {
        strcat(response, "  (No users registered yet)\n");
    } else {
        for (int i = 0; i < num_users; i++) {
            strcat(response, "  - ");
            strcat(response, registered_users[i]);
            strcat(response, "\n");
        }
    }
    
    pthread_mutex_unlock(&file_system_mutex);
    
    // Send response
    PacketHeader res_header;
    res_header.type = MSG_SUCCESS;
    res_header.size = strlen(response) + 1;
    write_all(client_sock, &res_header, sizeof(res_header));
    write_all(client_sock, response, res_header.size);
    
    LOG_INFO("Response: Sent list of %d users", num_users);
}

// Administrative: Reset all users and their data (except system-owned files)
void nm_handle_reset_users(int client_sock) {
    FileRequestPayload payload; memset(&payload,0,sizeof(payload));
    if (read_all(client_sock, &payload, sizeof(payload)) == -1) return;
    const char* requester = payload.username;
    // Authorization: only 'system' user may perform reset
    if (strcmp(requester, "system") != 0) {
        send_response(client_sock, MSG_ERROR, "Unauthorized: resetusers requires 'system' user.");
        LOG_WARN("Security: Unauthorized reset attempt by '%s'", requester);
        return;
    }
    pthread_mutex_lock(&file_system_mutex);
    // Delete all files (except those owned by system) by instructing SS
    int deleted = 0, failed = 0;
    for (int i=0;i<num_files;i++) {
        if (strcmp(file_index[i].owner_username, "system") == 0) continue; // Keep system files
        SSRegisterPayload ss = active_servers[file_index[i].server_index];
        int ss_sock = tcp_connect(ss.ip_addr, ss.client_port);
        if (ss_sock != -1) {
            PacketHeader h; FileRequestPayload p; h.type = MSG_SS_DELETE_FILE; h.size = sizeof(p); memset(&p,0,sizeof(p));
            strncpy(p.filename, file_index[i].filename, MAX_PATH_LEN);
            strncpy(p.username, requester, MAX_USERNAME_LEN); // system user initiates
            if (write_all(ss_sock, &h, sizeof(h)) == 0 && write_all(ss_sock, &p, sizeof(p)) == 0) {
                // Read response to avoid early close causing SIGPIPE on SS
                PacketHeader rh; ResponsePayload rp;
                if (read_all(ss_sock, &rh, sizeof(rh)) == 0 && rh.size <= (int)sizeof(rp) && read_all(ss_sock, &rp, rh.size) == 0 && rh.type == MSG_SUCCESS) {
                    deleted++;
                } else {
                    failed++;
                }
            } else {
                failed++;
            }
            close(ss_sock);
        } else {
            failed++;
        }
        // Light pacing every 50 deletions to be gentle on SS
        if ((deleted + failed) % 50 == 0) { usleep(2000); }
    }
    // Clear file index entries except system ones (compact array)
    int w=0; for (int i=0;i<num_files;i++) {
        if (strcmp(file_index[i].owner_username, "system") == 0) {
            if (w!=i) file_index[w] = file_index[i];
            w++;
        }
    }
    num_files = w;
    // Reset user registry to contain only system
    int new_num = 0;
    for (int i=0;i<num_users;i++) {
        if (strcmp(registered_users[i], "system") == 0) {
            strncpy(registered_users[new_num], "system", MAX_USERNAME_LEN); new_num = 1; break;
        }
    }
    num_users = new_num;
    save_file_index();
    save_user_registry();
    pthread_mutex_unlock(&file_system_mutex);
    char summary[256]; snprintf(summary, sizeof(summary), "Reset complete. Deleted: %d, Failed: %d. Remaining files: %d, users: %d", deleted, failed, num_files, num_users);
    send_response(client_sock, MSG_SUCCESS, summary);
    LOG_INFO("Administrative: Registry reset by '%s' (deleted=%d failed=%d remaining files=%d, users=%d)", requester, deleted, failed, num_files, num_users);
}

// Helper: run shell script via /bin/sh -c and capture stdout+stderr
static int run_shell_capture(const char* script, char* out, size_t outsz) {
    if (!script || !out || outsz == 0) return -1;
    int pipefd[2];
    if (pipe(pipefd) == -1) return -1;
    pid_t pid = fork();
    if (pid < 0) { close(pipefd[0]); close(pipefd[1]); return -1; }
    if (pid == 0) {
        // Child: redirect stdout and stderr to pipe, then exec sh -c script
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[0]);
        close(pipefd[1]);
        execl("/bin/sh", "sh", "-c", script, (char*)NULL);
        // If exec fails
        _exit(127);
    }
    // Parent
    close(pipefd[1]);
    ssize_t total = 0;
    while (total < (ssize_t)(outsz - 1)) {
        ssize_t n = read(pipefd[0], out + total, (outsz - 1) - (size_t)total);
        if (n <= 0) break;
        total += n;
    }
    close(pipefd[0]);
    out[total] = '\0';
    int status = 0; (void)waitpid(pid, &status, 0);
    // Return 0 on success, non-zero otherwise (but we still return captured output)
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    return -1;
}

void nm_handle_exec(int client_sock) {
    FileRequestPayload payload; 
    memset(&payload, 0, sizeof(payload));
    if (read_all(client_sock, &payload, sizeof(payload)) == -1) return;
    
    pthread_mutex_lock(&file_system_mutex);
    int file_idx = find_file_unsafe(payload.filename);
    if (file_idx == -1) { 
        pthread_mutex_unlock(&file_system_mutex); 
        send_response(client_sock, MSG_ERROR, "File not found."); 
        return; 
    }
    
    // Check if user has read permission to execute
    if (!check_permission(payload.username, file_idx, 0)) { 
        pthread_mutex_unlock(&file_system_mutex); 
        send_response(client_sock, MSG_ERROR, "Access Denied: You need read permission to execute."); 
        return; 
    }
    
    // Update last access time
    file_index[file_idx].last_access = time(NULL);
    int ss_index = file_index[file_idx].server_index;
    if (ss_index < 0 || ss_index >= num_servers || server_alive[ss_index] == 0) {
        pthread_mutex_unlock(&file_system_mutex);
        send_response(client_sock, MSG_ERROR, "503 Storage Server unavailable.");
        return;
    }
    SSRegisterPayload target_ss = active_servers[ss_index];
    pthread_mutex_unlock(&file_system_mutex);

    // Fetch file contents from SS
    int ss_sock = tcp_connect(target_ss.ip_addr, target_ss.client_port);
    if (ss_sock == -1) { send_response(client_sock, MSG_ERROR, "Failed to contact Storage Server."); return; }
    PacketHeader hdr; FileRequestPayload req; hdr.type = MSG_SS_READ_FILE; hdr.size = sizeof(req);
    memset(&req, 0, sizeof(req)); strncpy(req.username, payload.username, MAX_USERNAME_LEN); strncpy(req.filename, payload.filename, MAX_PATH_LEN);
    write_all(ss_sock, &hdr, sizeof(hdr)); write_all(ss_sock, &req, sizeof(req));
    PacketHeader rh; SSReadPayload rp;
    if (read_all(ss_sock, &rh, sizeof(rh)) == -1 || read_all(ss_sock, &rp, rh.size) == -1) { close(ss_sock); send_response(client_sock, MSG_ERROR, "No response from Storage Server."); return; }
    close(ss_sock);
    if (rh.type != MSG_SUCCESS) { send_response(client_sock, MSG_ERROR, "Failed to read file for execution."); return; }

    // Execute file content as shell commands on Name Server and capture output
    char script[MAX_MSG_LEN];
    strncpy(script, rp.content, sizeof(script)); script[sizeof(script)-1] = '\0';
    char output[MAX_MSG_LEN]; output[0] = '\0';
    int rc = run_shell_capture(script, output, sizeof(output));
    if (rc == 0) {
        // Success; return captured output (may be empty)
        send_response(client_sock, MSG_SUCCESS, output[0] ? output : "");
    } else {
        // Non-zero exit; still return whatever was captured, but mark as error
        if (output[0] == '\0') strncpy(output, "Command execution failed.", sizeof(output));
        send_response(client_sock, MSG_ERROR, output);
    }
    LOG_INFO("Request: Executed shell file '%s' by user '%s' (rc=%d)", payload.filename, payload.username, rc);
}

// --- Bonus Access Request Workflow ---
// Client requests access to a file
void nm_handle_request_access(int client_sock) {
    AccessRequestPayload payload; memset(&payload,0,sizeof(payload));
    if (read_all(client_sock,&payload,sizeof(payload))==-1) return;
    pthread_mutex_lock(&file_system_mutex);
    int file_idx = find_file_unsafe(payload.filename);
    if (file_idx == -1) { pthread_mutex_unlock(&file_system_mutex); send_response(client_sock, MSG_ERROR, "File not found."); return; }
    FileIndexEntry* fe = &file_index[file_idx];
    if (strcmp(payload.requester_username, fe->owner_username)==0) { pthread_mutex_unlock(&file_system_mutex); send_response(client_sock, MSG_ERROR, "Owner already has access."); return; }
    // Already has access?
    if (payload.requested_type) {
        // Requesting write: only reject if already has write
        if (check_permission(payload.requester_username, file_idx, 1)) { pthread_mutex_unlock(&file_system_mutex); send_response(client_sock, MSG_ERROR, "User already has write access."); return; }
        // If they only have read, allow an upgrade request
    } else {
        // Requesting read: reject if already has read
        if (check_permission(payload.requester_username, file_idx, 0)) { pthread_mutex_unlock(&file_system_mutex); send_response(client_sock, MSG_ERROR, "User already has access."); return; }
    }
    // Duplicate request?
    for (int i=0;i<fe->num_pending_requests;i++) {
        if (strcmp(fe->pending_req_user[i], payload.requester_username)==0) {
            // If existing pending is read but new is write, upgrade the pending type
            if (payload.requested_type && fe->pending_req_type[i]==0) {
                fe->pending_req_type[i] = 1; save_file_index(); pthread_mutex_unlock(&file_system_mutex);
                send_response(client_sock, MSG_SUCCESS, "Pending request upgraded to write."); return;
            }
            pthread_mutex_unlock(&file_system_mutex); send_response(client_sock, MSG_ERROR, "Access request already pending."); return;
        }
    }
    if (fe->num_pending_requests >= MAX_USERS) { pthread_mutex_unlock(&file_system_mutex); send_response(client_sock, MSG_ERROR, "Too many pending requests."); return; }
    strncpy(fe->pending_req_user[fe->num_pending_requests], payload.requester_username, MAX_USERNAME_LEN);
    fe->pending_req_type[fe->num_pending_requests] = payload.requested_type ? 1 : 0;
    fe->num_pending_requests++;
    save_file_index();
    pthread_mutex_unlock(&file_system_mutex);
    send_response(client_sock, MSG_SUCCESS, "Access request recorded.");
    LOG_INFO("Request: Access requested by '%s' for file '%s' type=%s", payload.requester_username, payload.filename, payload.requested_type?"RW":"R");
}

// Owner lists pending requests
void nm_handle_list_access_requests(int client_sock) {
    AccessListQueryPayload payload; memset(&payload,0,sizeof(payload));
    if (read_all(client_sock,&payload,sizeof(payload))==-1) return;
    pthread_mutex_lock(&file_system_mutex);
    int file_idx = find_file_unsafe(payload.filename);
    if (file_idx == -1) { pthread_mutex_unlock(&file_system_mutex); send_response(client_sock, MSG_ERROR, "File not found."); return; }
    FileIndexEntry* fe = &file_index[file_idx];
    if (strcmp(payload.owner_username, fe->owner_username)!=0) { pthread_mutex_unlock(&file_system_mutex); send_response(client_sock, MSG_ERROR, "Access Denied: Only owner can list requests."); return; }
    char out[MAX_MSG_LEN]; out[0]='\0';
    if (fe->num_pending_requests==0) {
        strncpy(out, "(no pending requests)", sizeof(out));
    } else {
        for (int i=0;i<fe->num_pending_requests;i++) {
            char line[128]; snprintf(line,sizeof(line), "%s:%s\n", fe->pending_req_user[i], fe->pending_req_type[i]?"RW":"R");
            if (strlen(out)+strlen(line)+1 < sizeof(out)) strcat(out,line);
        }
    }
    pthread_mutex_unlock(&file_system_mutex);
    send_response(client_sock, MSG_SUCCESS, out);
}

// Owner approves or denies a pending request
void nm_handle_decide_access(int client_sock) {
    AccessDecisionPayload payload; memset(&payload,0,sizeof(payload));
    if (read_all(client_sock,&payload,sizeof(payload))==-1) return;
    pthread_mutex_lock(&file_system_mutex);
    int file_idx = find_file_unsafe(payload.filename);
    if (file_idx == -1) { pthread_mutex_unlock(&file_system_mutex); send_response(client_sock, MSG_ERROR, "File not found."); return; }
    FileIndexEntry* fe = &file_index[file_idx];
    if (strcmp(payload.owner_username, fe->owner_username)!=0) { pthread_mutex_unlock(&file_system_mutex); send_response(client_sock, MSG_ERROR, "Access Denied: Only owner can decide."); return; }
    int pos=-1; for (int i=0;i<fe->num_pending_requests;i++) if (strcmp(fe->pending_req_user[i], payload.target_username)==0) { pos=i; break; }
    if (pos==-1) { pthread_mutex_unlock(&file_system_mutex); send_response(client_sock, MSG_ERROR, "No such pending request."); return; }
    if (payload.approve) {
        // Find existing ACL entry, if any
        int acl_idx = -1; for (int j=0; j<fe->num_acl_entries; j++) { if (strcmp(fe->acl[j].username, payload.target_username)==0) { acl_idx = j; break; } }
        int req_write = fe->pending_req_type[pos] ? 1 : 0;
        if (acl_idx >= 0) {
            // User already has read access; if write requested, upgrade
            if (req_write && !fe->acl[acl_idx].has_write_access) {
                fe->acl[acl_idx].has_write_access = 1;
            }
        } else {
            // No existing entry; add new ACL entry with requested rights
            if (fe->num_acl_entries < MAX_USERS) {
                strncpy(fe->acl[fe->num_acl_entries].username, payload.target_username, MAX_USERNAME_LEN);
                fe->acl[fe->num_acl_entries].has_write_access = req_write ? 1 : 0;
                fe->num_acl_entries++;
            } else {
                pthread_mutex_unlock(&file_system_mutex); send_response(client_sock, MSG_ERROR, "ACL full; cannot grant access."); return; }
        }
    }
    // Remove request (compact array)
    for (int i=pos;i<fe->num_pending_requests-1;i++) {
        strncpy(fe->pending_req_user[i], fe->pending_req_user[i+1], MAX_USERNAME_LEN);
        fe->pending_req_type[i] = fe->pending_req_type[i+1];
    }
    fe->num_pending_requests--;
    save_file_index();
    pthread_mutex_unlock(&file_system_mutex);
    if (payload.approve) send_response(client_sock, MSG_SUCCESS, "Request approved."); else send_response(client_sock, MSG_SUCCESS, "Request denied.");
    LOG_INFO("Request: Owner '%s' %s access for '%s' on file '%s'", payload.owner_username, payload.approve?"approved":"denied", payload.target_username, payload.filename);
}

// Owner: list all files owned by them with pending request counts
void nm_handle_list_owner_files(int client_sock) {
    OwnerFilesQueryPayload payload; memset(&payload,0,sizeof(payload));
    if (read_all(client_sock,&payload,sizeof(payload))==-1) return;
    pthread_mutex_lock(&file_system_mutex);
    // Gather indices of files owned by this user
    int idx[MAX_FILES]; int count=0;
    for (int i=0;i<num_files;i++) {
        if (file_index[i].filename[0]=='\0') continue;
        if (strcmp(file_index[i].owner_username, payload.owner_username)==0) {
            idx[count++]=i;
        }
    }
    // Sort by filename for stability
    for (int a=0;a<count;a++) for (int b=a+1;b<count;b++) if (strcasecmp(file_index[idx[a]].filename, file_index[idx[b]].filename)>0) { int t=idx[a]; idx[a]=idx[b]; idx[b]=t; }
    char out[MAX_MSG_LEN]; out[0]='\0';
    if (count==0) {
        strncpy(out, "(no files owned)", sizeof(out));
    } else {
        int digits = (count<10)?1:((count<100)?2:3);
        for (int k=0;k<count;k++) {
            int i = idx[k];
            int pend = file_index[i].num_pending_requests;
            char line[256];
            snprintf(line, sizeof(line), "%*d) %s | pending_requests = %d\n", digits, k+1, file_index[i].filename, pend);
            if (strlen(out)+strlen(line)+1 < sizeof(out)) strcat(out, line);
        }
    }
    pthread_mutex_unlock(&file_system_mutex);
    send_response(client_sock, MSG_SUCCESS, out);
}

// --- Checkpoint handlers ---
static int forward_to_ss_checkpoint(int file_idx, MessageType t, const void* payload, int payload_size, ResponsePayload* out, MessageType* out_type) {
    int ss_index = file_index[file_idx].server_index;
    if (ss_index < 0 || ss_index >= num_servers || server_alive[ss_index] == 0) { return -1; }
    SSRegisterPayload target_ss = active_servers[ss_index];
    pthread_mutex_unlock(&file_system_mutex);
    int ss_sock = tcp_connect(target_ss.ip_addr, target_ss.client_port);
    if (ss_sock == -1) { return -1; }
    PacketHeader h={.type=t,.size=payload_size}; write_all(ss_sock,&h,sizeof(h)); write_all(ss_sock,payload,payload_size);
    PacketHeader rh; ResponsePayload rp; if (read_all(ss_sock,&rh,sizeof(rh))==-1 || read_all(ss_sock,&rp,rh.size)==-1) { close(ss_sock); return -1; }
    close(ss_sock); if (out) *out = rp; if (out_type) *out_type = rh.type; return 0;
}

void nm_handle_checkpoint(int client_sock) {
    CheckpointTagPayload p; memset(&p,0,sizeof(p)); if (read_all(client_sock,&p,sizeof(p))==-1) return;
    pthread_mutex_lock(&file_system_mutex); int idx=find_file_unsafe(p.filename); if (idx==-1) { pthread_mutex_unlock(&file_system_mutex); send_response(client_sock, MSG_ERROR, "File not found."); return; }
    if (!check_permission(p.username, idx, 1)) { pthread_mutex_unlock(&file_system_mutex); send_response(client_sock, MSG_ERROR, "Access Denied: write required."); return; }
    ResponsePayload rp; MessageType rt; if (forward_to_ss_checkpoint(idx, MSG_SS_CHECKPOINT_CREATE, &p, sizeof(p), &rp, &rt)!=0) { send_response(client_sock, MSG_ERROR, "Failed to contact Storage Server."); return; }
    // Not modifying file, but update last_access
    pthread_mutex_lock(&file_system_mutex); if (idx>=0) file_index[idx].last_access=time(NULL); pthread_mutex_unlock(&file_system_mutex);
    send_response(client_sock, rt, rp.message);
}
void nm_handle_view_checkpoint(int client_sock) {
    CheckpointTagPayload p; memset(&p,0,sizeof(p)); if (read_all(client_sock,&p,sizeof(p))==-1) return;
    pthread_mutex_lock(&file_system_mutex); int idx=find_file_unsafe(p.filename); if (idx==-1) { pthread_mutex_unlock(&file_system_mutex); send_response(client_sock, MSG_ERROR, "File not found."); return; }
    if (!check_permission(p.username, idx, 0)) { pthread_mutex_unlock(&file_system_mutex); send_response(client_sock, MSG_ERROR, "Access Denied."); return; }
    ResponsePayload rp; MessageType rt; if (forward_to_ss_checkpoint(idx, MSG_SS_CHECKPOINT_VIEW, &p, sizeof(p), &rp, &rt)!=0) { send_response(client_sock, MSG_ERROR, "Failed to contact Storage Server."); return; }
    pthread_mutex_lock(&file_system_mutex); if (idx>=0) file_index[idx].last_access=time(NULL); pthread_mutex_unlock(&file_system_mutex);
    send_response(client_sock, rt, rp.message);
}
void nm_handle_revert_checkpoint(int client_sock) {
    CheckpointTagPayload p; memset(&p,0,sizeof(p)); if (read_all(client_sock,&p,sizeof(p))==-1) return;
    pthread_mutex_lock(&file_system_mutex); int idx=find_file_unsafe(p.filename); if (idx==-1) { pthread_mutex_unlock(&file_system_mutex); send_response(client_sock, MSG_ERROR, "File not found."); return; }
    if (!check_permission(p.username, idx, 1)) { pthread_mutex_unlock(&file_system_mutex); send_response(client_sock, MSG_ERROR, "Access Denied: write required."); return; }
    ResponsePayload rp; MessageType rt; if (forward_to_ss_checkpoint(idx, MSG_SS_CHECKPOINT_REVERT, &p, sizeof(p), &rp, &rt)!=0) { send_response(client_sock, MSG_ERROR, "Failed to contact Storage Server."); return; }
    if (rt==MSG_SUCCESS) { pthread_mutex_lock(&file_system_mutex); if (idx>=0) { file_index[idx].modified_time=time(NULL); file_index[idx].last_access=time(NULL);} pthread_mutex_unlock(&file_system_mutex); }
    send_response(client_sock, rt, rp.message);
}
void nm_handle_list_checkpoints(int client_sock) {
    CheckpointListPayload p; memset(&p,0,sizeof(p)); if (read_all(client_sock,&p,sizeof(p))==-1) return;
    pthread_mutex_lock(&file_system_mutex); int idx=find_file_unsafe(p.filename); if (idx==-1) { pthread_mutex_unlock(&file_system_mutex); send_response(client_sock, MSG_ERROR, "File not found."); return; }
    if (!check_permission(p.username, idx, 0)) { pthread_mutex_unlock(&file_system_mutex); send_response(client_sock, MSG_ERROR, "Access Denied."); return; }
    ResponsePayload rp; MessageType rt; if (forward_to_ss_checkpoint(idx, MSG_SS_CHECKPOINT_LIST, &p, sizeof(p), &rp, &rt)!=0) { send_response(client_sock, MSG_ERROR, "Failed to contact Storage Server."); return; }
    pthread_mutex_lock(&file_system_mutex); if (idx>=0) file_index[idx].last_access=time(NULL); pthread_mutex_unlock(&file_system_mutex);
    send_response(client_sock, rt, rp.message);
}

// --- Heartbeat monitoring ---
static void* heartbeat_thread(void* arg) {
    (void)arg;
    const int interval_ms = 2000; // 2s interval
    while (1) {
        usleep(interval_ms * 1000);
        pthread_mutex_lock(&file_system_mutex);
        int local_num = num_servers;
        SSRegisterPayload servers[MAX_SERVERS];
        for (int i=0;i<local_num;i++) servers[i] = active_servers[i];
        pthread_mutex_unlock(&file_system_mutex);
        for (int i=0;i<local_num;i++) {
            int sock = tcp_connect(servers[i].ip_addr, servers[i].client_port);
            if (sock == -1) {
                if (server_alive[i]) LOG_WARN("Heartbeat: SS %s:%d DOWN", servers[i].ip_addr, servers[i].client_port);
                server_alive[i] = 0;
                continue;
            }
            // Minimal ping: immediately close after successful connect
            close(sock);
            if (!server_alive[i]) LOG_INFO("Heartbeat: SS %s:%d UP", servers[i].ip_addr, servers[i].client_port);
            server_alive[i] = 1;
        }
    }
    return NULL;
}

void nm_start_heartbeat_monitor() {
    pthread_t tid; if (pthread_create(&tid, NULL, heartbeat_thread, NULL) == 0) pthread_detach(tid);
}
