# Network File System (NFS) - Distributed Document System

A multi-threaded distributed file system with Name Server coordination, Storage Server persistence, and multi-client support with access control.

## Quick Start

### Build
```bash
make
```

### Run Servers
```bash
# Terminal 1: Name Server
./bin/nm 8081

# Terminal 2: Storage Server
./bin/ss <my_ip> 127.0.0.1 8081 9091
# Example for localhost: ./bin/ss 127.0.0.1 127.0.0.1 8081 9091
# Example for network:   ./bin/ss 192.168.1.10 192.168.1.5 8081 9091

# Terminal 3+: Client(s)
./bin/client 127.0.0.1 8081
```

**Graceful Shutdown**: Press `Ctrl+C` to stop servers cleanly.

### Command Line Arguments

**Name Server:**
```bash
./bin/nm <port>
```
- `<port>`: Port number for Name Server (e.g., 8081)

**Storage Server:**
```bash
./bin/ss <my_ip> <nm_ip> <nm_port> <ss_port>
```
- `<my_ip>`: **IP address of this Storage Server** (e.g., `127.0.0.1` for localhost, or `192.168.1.10` for network)
- `<nm_ip>`: IP address of Name Server (e.g., `127.0.0.1`)
- `<nm_port>`: Port of Name Server (e.g., `8081`)
- `<ss_port>`: Port for Storage Server to listen on (e.g., `9091`)

**Client:**
```bash
./bin/client <nm_ip> <nm_port>
```
- `<nm_ip>`: IP address of Name Server
- `<nm_port>`: Port of Name Server

**Note**: To run on different devices, use the actual network IP addresses (e.g., `192.168.x.x`) instead of `127.0.0.1`. All devices must be on the same network.

## Core Functionalities

### File Operations
| Command | Description | Usage |
|---------|-------------|-------|
| `create` | Create new file | `create <filename>` |
| `read` | Read file contents | `read <filename>` |
| `write` | Write to file | `write <filename> <content>` |
| `write` | Edit sentence | `write <filename> <sentence_num>` then `<word_index> <content>` ... `ETIRW` |
| `delete` | Delete file | `delete <filename>` |
| `view` | List accessible files | `view` / `view -a` / `view -l` / `view -al` |
| `info` | File metadata | `info <filename>` |

**Important** (indexing & editing rules):
- **Sentences (0-based)**: Sentence 0 is the first complete sentence. A sentence is counted only if it ends with one of `.`, `!`, `?`.
- **Words (0-based)**: Within an active sentence editing session, word 0 is the first word.
- **Word insertion (during edit)**: Entering `<word_index> <content>` inserts the new content *before* the word currently at that index (shifts words right). Using the last index (equal to current word count) appends.
- **Automatic sentence splitting**: If, during editing, the working sentence contains delimiters (`. ! ?`), each delimiter terminates the current sentence and begins a new one on commit. Example: starting from `hello world!` then inserting `dhyey.` at word index 0 yields two sentences after commit:
  - Sentence 0: `dhyey.`
  - Sentence 1: `hello world!`
- **Delimiter preservation**: Original sentence-ending delimiter is retained unless you explicitly change it.
- **Edit ordering constraint**: You cannot begin editing sentence N+1 until sentence N has a terminating delimiter.

### Advanced Features
| Command | Description | Usage |
|---------|-------------|-------|
| `stream` | Stream file word-by-word (0.1s delay) | `stream <filename>` |
| `undo` | Revert last change | `undo <filename>` |
| `exec` | Execute file as shell commands | `exec <filename>` |
| `list` | List registered users | `list` |

### Access Control
| Command | Description | Usage |
|---------|-------------|-------|
| `addaccess` | Grant read access | `addaccess -R <filename> <username>` |
| `addaccess` | Grant write access | `addaccess -W <filename> <username>` |
| `remaccess` | Revoke access | `remaccess <filename> <username>` |

## Bonus Features

### Folder Hierarchy
| Command | Description | Usage |
|---------|-------------|-------|
| `createfolder` | Create folder | `createfolder <foldername>` |
| `move` | Move file to folder | `move <filename> <foldername>` |
| `viewfolder` | List folder contents | `viewfolder <foldername>` |
| `deletefolder` | Delete folder | `deletefolder <foldername>` |

**Note**: `.` represents the root folder. Use `viewfolder .` to view all files in the root directory.

### Checkpoints (Versioning)
| Command | Description | Usage |
|---------|-------------|-------|
| `checkpoint` | Create checkpoint | `checkpoint <filename> <tag>` |
| `viewcheckpoint` | View checkpoint content | `viewcheckpoint <filename> <tag>` |
| `revert` | Revert to checkpoint | `revert <filename> <tag>` |
| `listcheckpoints` | List all checkpoints | `listcheckpoints <filename>` |

### Access Requests
| Command | Description | Usage |
|---------|-------------|-------|
| `requestaccess` | Request file access | `requestaccess <filename> <R\|W>` |
| `listrequests` | View pending requests (owner) | `listrequests <filename>` |
| `approvereq` | Approve request (owner) | `approvereq <filename> <username>` |
| `denyreq` | Deny request (owner) | `denyreq <filename> <username>` |

### Additional Commands
- `myfiles` - List files you own
- `exit` - Exit client
- `resetusers` - (admin only: username `system`) Remove all registered users and their non-system files. Keeps `system` user and files it owns.

### Admin User (`system`)
- **Full Access**: The admin user `system` can read, write, and delete any file regardless of ownership or ACL.
- **User Registry Reset**: `resetusers` wipes all non-system users and deletes their files across all Storage Servers. System-owned files are preserved.
- **Access Control**: Owners manage ACLs; admin access does not require ACL entries and bypasses permission checks.

### Persistence Metadata Files
The Name Server persists its state across restarts using three metadata files stored in its working directory:

- `nm_file_index.dat`: Binary catalog of all tracked files. Layout: magic header (`NMFI`), version (currently 2), file count, then an array of file entries. Each entry stores: filename (may include folder prefix), storage server index, owner username, ACL entries (user + RW flag), timestamps (`created`, `modified`, `last_access`), and pending access request queues. On startup this is loaded; a hash table and small LRU cache are rebuilt in memory for fast lookups. If deleted, the Name Server starts fresh and re-imports any files reported by Storage Servers as `system` owned.
- `nm_user_registry.dat`: Binary list of registered usernames. Layout: user count followed by fixed-size username blocks. After `resetusers`, only the `system` user remains. Deleting this file causes the Name Server to start with an empty user list (users re-register on first activity).
- `nm_folders.dat`: Binary list of created folder paths (normalized without trailing slash). Layout: folder count followed by fixed-size path blocks. Used to support folder hierarchy queries (`viewfolder`, `move`). Not modified by `resetusers`; deleting it clears the folder registry but existing files whose names embed folder prefixes still appear.

Removal Guidance:
- Use the `resetusers` command (as `system`) for a logical cleanup that preserves system-owned files and folders.
- For a full metadata wipe, stop the Name Server and delete all three files; on restart, any surviving file data on Storage Servers becomes owned by `system` and prior ACL/user history is lost.
- Avoid truncating these files manually; remove them entirely if performing a hard reset.

These files are implementation details—no manual edit is required for normal operation.

## System Highlights

### Architecture
- **Name Server (NM)**: Central coordinator, file location mapping, access control
- **Storage Server (SS)**: File storage, concurrent access handling, undo history
- **Client**: Multi-user interface with username-based authentication

### Key Features
- ✅ **Multi-Client Support**: Single Name Server instance supports multiple Storage Servers and Clients connecting/disconnecting dynamically
- ✅ **Concurrent Access**: Multiple clients can read/write simultaneously with sentence-level locking
- ✅ **Data Persistence**: Files, metadata, and ACLs survive server restarts
- ✅ **Efficient Search**: O(1) average-case file lookup using **Hash Table** with 211 buckets (prime number for better distribution)
  - Search algorithm: **Hash Map (djb2 algorithm)** for file name lookups
  - Faster than O(N) linear search as required by specifications
  - Efficient metadata retrieval without full index scanning
- ✅ **STREAM Feature**: Word-by-word streaming with precise 0.1s delays (`usleep(100000)`)
- ✅ **Logging**: Timestamped request/response tracking on NM and SS
- ✅ **Error Handling**: Comprehensive error codes and messages
- ✅ **Graceful Shutdown**: Signal handling (SIGINT/SIGTERM) for clean exits
- ✅ **Dynamic Scaling**: Storage Servers can join at any time; system handles disconnections gracefully
- ✅ **Admin Reset**: `resetusers` purges user registry & non-system files (authorized only for `system` user)

### Write Operations
The `WRITE` command supports sentence-level editing:
```bash
write file.txt 0          # Edit sentence 0
> 1 Hello                 # Replace word at index 1
> 3 world!                # Replace word at index 3
> ETIRW                   # Complete write (releases lock)
```

### Access Levels
- **Owner**: Full read/write access (cannot be revoked)
- **Write (W)**: Read and write access
- **Read (R)**: Read-only access
- **None**: No access

## Cleanup
```bash
make clean        # Remove binaries
make clean-all    # Remove all generated files
make kill-servers # Stop all running servers
```

## Project Structure
```
├── bin/              # Compiled executables (nm, ss, client)
├── src/
│   ├── client/       # Client interface and logic
│   ├── common/       # Protocol, network utilities, logger
│   ├── name_server/  # Name server with hash-based file indexing
│   └── storage_server/ # Storage with sentence locking and undo
└── Makefile          # Build and run targets
```

## Implementation Notes
- **Sentence Delimiter**: Period (`.`), exclamation (`!`), question mark (`?`)
- **Word Separator**: Space character
- **Concurrency**: Pthread-based with mutex protection
- **File Locking**: Sentence-level locks during WRITE operations
- **Undo Mechanism**: One-level undo per file (storage server maintains history)
- **EXEC Security**: Runs on Name Server, output piped to client

---

## Team Members

**The Critical Section**

1. **Dhyey Thummar** - Roll No: 2024101024
2. **Ayush Kanani** - Roll No: 2024101049

**Course**: Operating Systems and Networks (CS3301)
