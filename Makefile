## Simple Makefile to build Name Server (nm), Storage Server (ss), and Client (client)

CC      := cc
CFLAGS  := -Wall -Wextra -O2 -pthread -Isrc/common
LDFLAGS := -pthread

BIN_DIR := bin

COMMON_SRC  := src/common/network.c src/common/logger.c
NM_SRC      := src/name_server/nm_main.c src/name_server/nm_logic.c $(COMMON_SRC)
SS_SRC      := src/storage_server/ss_main.c src/storage_server/ss_logic.c $(COMMON_SRC)
CLIENT_SRC  := src/client/client_main.c src/client/client_logic.c

NM_BIN      := $(BIN_DIR)/nm
SS_BIN      := $(BIN_DIR)/ss
CLIENT_BIN  := $(BIN_DIR)/client

.PHONY: all clean clean-all run-nm run-ss run-client kill-servers

all: $(NM_BIN) $(SS_BIN) $(CLIENT_BIN)

$(BIN_DIR):
	@mkdir -p $(BIN_DIR)

$(NM_BIN): $(NM_SRC) | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $(NM_SRC) $(LDFLAGS)

$(SS_BIN): $(SS_SRC) | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $(SS_SRC) $(LDFLAGS)

$(CLIENT_BIN): $(CLIENT_SRC) | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $(CLIENT_SRC) $(LDFLAGS)

## Convenience run targets (UPDATED: dynamic NM port)
## Variables (override on command line):
##   NM_PORT   - Name Server port (required for run-nm, run-ss, run-client)
##   NM_IP     - Name Server IP (default 127.0.0.1)
##   SS_PORT   - Storage Server port (default 9090)
## Examples:
##   make run-nm NM_PORT=8081
##   make run-ss NM_PORT=8081 SS_PORT=9091
##   make run-client NM_PORT=8081
## One-liners:
##   make run-nm NM_PORT=8081 & \
##   make run-ss NM_PORT=8081 SS_PORT=9091 & \
##   make run-client NM_PORT=8081

NM_IP    ?= 127.0.0.1
SS_PORT  ?= 9090
NM_PORT  ?= 

run-nm: $(NM_BIN)
	@if [ -z "$(NM_PORT)" ]; then echo "Error: NM_PORT not set. Usage: make run-nm NM_PORT=<port>"; exit 1; fi
	@echo "Starting Name Server on port $(NM_PORT)..."
	@echo "Note: If you get 'Address already in use', run: make kill-servers"
	$(NM_BIN) $(NM_PORT)

run-ss: $(SS_BIN)
	@if [ -z "$(NM_PORT)" ]; then echo "Error: NM_PORT not set. Usage: make run-ss NM_PORT=<nm_port> SS_PORT=<ss_port>"; exit 1; fi
	@echo "Starting Storage Server on port $(SS_PORT), connecting to NM at $(NM_IP):$(NM_PORT)..."
	@echo "Note: If you get 'Address already in use', run: make kill-servers"
	$(SS_BIN) $(NM_IP) $(NM_PORT) $(SS_PORT)

run-client: $(CLIENT_BIN)
	@if [ -z "$(NM_PORT)" ]; then echo "Error: NM_PORT not set. Usage: make run-client NM_PORT=<nm_port>"; exit 1; fi
	@echo "Connecting to Name Server at $(NM_IP):$(NM_PORT)..."
	@trap '' INT; $(CLIENT_BIN) $(NM_IP) $(NM_PORT)

## Helper target to kill any running servers
kill-servers:
	@echo "Killing all server processes..."
	@pkill -f "bin/nm" 2>/dev/null || true
	@pkill -f "bin/ss" 2>/dev/null || true
	@pkill -f "bin/client" 2>/dev/null || true
	@if command -v lsof >/dev/null 2>&1; then \
		for port in 8080 8081 8082 9090 9091 9092; do \
			pids=$$(lsof -t -i:$$port 2>/dev/null); \
			if [ -n "$$pids" ]; then \
				echo "Killing processes on port $$port: $$pids"; \
				kill $$pids 2>/dev/null || true; \
			fi; \
		done; \
	fi
	@echo "All servers killed"

clean:
	rm -rf $(BIN_DIR)

clean-all: clean
	@echo "Removing all generated files, logs, and test data..."
	@rm -f *.log *.out *.tmp osn_writeup2.txt a.sh new.sh 2>/dev/null || true
	@rm -f .nm.out .nm.test.out .ss.out nm_manual.out ss_manual.out 2>/dev/null || true
	@rm -f test_results.log test_all.sh test_exec_security.sh test_hard.sh test_quick.sh 2>/dev/null || true
	@rm -f nm_file_index.dat nm_user_registry.dat nm_folders.dat 2>/dev/null || true
	@rm -rf .test_ss_data 2>/dev/null || true
	@echo "All clean!"

