#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <dirent.h>
#include "../common/protocol.h"
#include "../common/network.h"
#include "../common/logger.h"

// Lock/session structures and helpers are adapted from previous ss_main.c
static void mkdirs_recursive(const char* path);
typedef struct {
    char filename[MAX_PATH_LEN];
    int sentence_number;
    char locked_by_user[MAX_USERNAME_LEN];
    int session_id; // uniquely bind lock to a client session
} SentenceLock;

typedef struct {
    char filename[MAX_PATH_LEN];
    int sentence_number;
    char owner_user[MAX_USERNAME_LEN];
    char base_content[MAX_MSG_LEN];
    char original_sentence[MAX_MSG_LEN];
    char original_delim;
    char working_sentence[MAX_MSG_LEN];
    char sentence_delim;
    int is_new_sentence;
    int session_id; // match the lock owner's session
} SentenceSession;

static SentenceLock active_locks[MAX_FILES * 10];
static int num_active_locks = 0;
static pthread_mutex_t lock_list_mutex = PTHREAD_MUTEX_INITIALIZER;
static SentenceSession sessions[MAX_FILES * 10];
static int num_sessions = 0;

static int find_lock_index(const char* filename, int sentence_number) {
    for (int i = 0; i < num_active_locks; i++) {
        if (strcmp(active_locks[i].filename, filename) == 0 && active_locks[i].sentence_number == sentence_number) return i;
    }
    return -1;
}
static int find_session_index(const char* filename, int sentence_number) {
    for (int i = 0; i < num_sessions; i++) {
        if (strcmp(sessions[i].filename, filename) == 0 && sessions[i].sentence_number == sentence_number) return i;
    }
    return -1;
}
static void trim(char* s) { int n = (int)strlen(s); while (n>0 && (s[n-1]==' '||s[n-1]=='\t'||s[n-1]=='\n'||s[n-1]=='\r')) s[--n]='\0'; int i=0; while (s[i]==' '||s[i]=='\t') i++; if (i>0) memmove(s, s+i, strlen(s+i)+1); }
static int find_sentence_bounds(const char* content, int target_idx, int* out_start, int* out_len, char* out_delim) {
    int idx = 0; int start = 0; for (int i=0; content[i] != '\0'; i++) { if (content[i]=='.'||content[i]=='!'||content[i]=='?') { int len=i-start; if (idx==target_idx) { if(out_start)*out_start=start; if(out_len)*out_len=len; if(out_delim)*out_delim=content[i]; return 0; } idx++; start=i+1; while (content[start]==' ') start++; } } return -1; }
static int count_sentences(const char* content) { int idx=0; for (int i=0; content[i]!='\0'; i++) if (content[i]=='.'||content[i]=='!'||content[i]=='?') idx++; return idx; }
static int apply_word_update(char* working, int word_index, const char* content) {
    // INSERTION semantics: insert content at word_index, shifting existing words to the right
    // word_index == cnt means append at end. Negative or >cnt is invalid.
    char buffer[MAX_MSG_LEN]; strncpy(buffer, working, sizeof(buffer)); buffer[sizeof(buffer)-1]='\0';
    char* words[1024]; int cnt=0; char* tok = strtok(buffer, " "); while (tok && cnt<1024) { words[cnt++]=tok; tok=strtok(NULL, " "); }
    if (word_index < 0 || word_index > cnt) return -1;
    char out[MAX_MSG_LEN]; out[0]='\0';
    
    for (int i=0;i<=cnt;i++) {
        if (i == word_index) {
            if (strlen(out) && out[strlen(out)-1] != ' ') { if (strlen(out)+1>=sizeof(out)) return -1; strcat(out, " "); }
            if (strlen(out)+strlen(content) >= sizeof(out)) return -1; strcat(out, content);
            if (i < cnt) { if (strlen(out)+1>=sizeof(out)) return -1; strcat(out, " "); }
        }
        if (i < cnt) {
            if (strlen(out)+strlen(words[i]) >= sizeof(out)) return -1; strcat(out, words[i]);
            if (i < cnt-1) { if (strlen(out)+1>=sizeof(out)) return -1; strcat(out, " "); }
        }
    }
    strncpy(working, out, MAX_MSG_LEN); working[MAX_MSG_LEN-1]='\0'; return 0;
}
static int init_session(const char* filename, int sentence_number, const char* user, int session_id, SentenceSession* out) {
    FILE* fp=fopen(filename, "r"); if(!fp) return -1; char content[MAX_MSG_LEN]; size_t n=fread(content,1,sizeof(content)-1,fp); fclose(fp); content[n]='\0';
    
    // Check if trying to edit sentence N+1 when sentence N has no delimiter
    int scount = count_sentences(content);
    if (sentence_number > scount) {
        // Trying to skip ahead - not allowed if previous sentence incomplete
        return -1;
    }
    
    int start=0,len=0; char delim='.'; if (find_sentence_bounds(content, sentence_number, &start, &len, &delim)!=0) {
        int scount = count_sentences(content);
        // Identify trailing incomplete fragment (text after last delimiter)
        int last_delim_pos = -1; for (int i=0; content[i]!='\0'; i++) if (content[i]=='.'||content[i]=='!'||content[i]=='?') last_delim_pos=i;
        int trailing_start = (last_delim_pos>=0)? last_delim_pos+1 : 0; while (content[trailing_start]==' '||content[trailing_start]=='\t') trailing_start++;
        int has_trailing_fragment = content[trailing_start] != '\0';

        // Case A: Editing the very first incomplete sentence (no delimiters yet, content non-empty)
        if (scount == 0 && sentence_number == 0 && has_trailing_fragment) {
            memset(out,0,sizeof(*out));
            strncpy(out->filename, filename, MAX_PATH_LEN);
            out->sentence_number = 0;
            strncpy(out->owner_user, user, MAX_USERNAME_LEN);
            strncpy(out->base_content, content, MAX_MSG_LEN);
            out->sentence_delim = '.'; out->original_delim='.';
            strncpy(out->original_sentence, content, MAX_MSG_LEN);
            out->original_sentence[MAX_MSG_LEN-1]='\0'; trim(out->original_sentence);
            strncpy(out->working_sentence, out->original_sentence, MAX_MSG_LEN);
            out->is_new_sentence = 0; out->session_id = session_id; return 0;
        }
        // Case B: Editing trailing incomplete fragment after at least one complete sentence
        if (sentence_number == scount && scount > 0 && has_trailing_fragment) {
            memset(out,0,sizeof(*out));
            strncpy(out->filename, filename, MAX_PATH_LEN);
            out->sentence_number = scount; // index is number of complete sentences
            strncpy(out->owner_user, user, MAX_USERNAME_LEN);
            strncpy(out->base_content, content, MAX_MSG_LEN);
            out->sentence_delim='.'; out->original_delim='.';
            strncpy(out->original_sentence, content+trailing_start, MAX_MSG_LEN);
            out->original_sentence[MAX_MSG_LEN-1]='\0'; trim(out->original_sentence);
            strncpy(out->working_sentence, out->original_sentence, MAX_MSG_LEN);
            out->is_new_sentence = 0; out->session_id=session_id; return 0;
        }
        // Case C: Create brand new empty sentence at the end (no trailing fragment there)
        if (sentence_number == scount && !has_trailing_fragment) {
            memset(out,0,sizeof(*out)); strncpy(out->filename, filename, MAX_PATH_LEN); out->sentence_number=scount; strncpy(out->owner_user, user, MAX_USERNAME_LEN); strncpy(out->base_content, content, MAX_MSG_LEN); out->sentence_delim='.'; out->original_delim='.'; out->original_sentence[0]='\0'; out->working_sentence[0]='\0'; out->is_new_sentence=1; out->session_id=session_id; return 0;
        }
        return -1;
    }
    memset(out,0,sizeof(*out)); strncpy(out->filename, filename, MAX_PATH_LEN); out->sentence_number=sentence_number; strncpy(out->owner_user, user, MAX_USERNAME_LEN); strncpy(out->base_content, content, MAX_MSG_LEN); out->sentence_delim=delim; out->original_delim=delim; int copy_len=len; if (copy_len>=MAX_MSG_LEN) copy_len=MAX_MSG_LEN-1; strncpy(out->original_sentence, content+start, copy_len); out->original_sentence[copy_len]='\0'; trim(out->original_sentence); strncpy(out->working_sentence, out->original_sentence, MAX_MSG_LEN); out->is_new_sentence=0; out->session_id=session_id; return 0;
}
static int recalc_current_index_and_update_lock(SentenceSession* s) {
    FILE* fp=fopen(s->filename, "r"); if(!fp) return -1; char content[MAX_MSG_LEN]; size_t n=fread(content,1,sizeof(content)-1,fp); fclose(fp); content[n]='\0';
    if (s->is_new_sentence) { int scount = count_sentences(content); pthread_mutex_lock(&lock_list_mutex); int lidx=find_lock_index(s->filename, s->sentence_number); s->sentence_number=scount; if (lidx>=0) active_locks[lidx].sentence_number=scount; pthread_mutex_unlock(&lock_list_mutex); return 0; }
    int idx=0,start=0; for (int i=0; content[i]!='\0'; i++) { if (content[i]=='.'||content[i]=='!'||content[i]=='?') { int len=i-start; char tmp[MAX_MSG_LEN]; int copy_len=len; if (copy_len>=MAX_MSG_LEN) copy_len=MAX_MSG_LEN-1; strncpy(tmp, content+start, copy_len); tmp[copy_len]='\0'; trim(tmp); if (strcmp(tmp, s->original_sentence)==0) { pthread_mutex_lock(&lock_list_mutex); int lidx=find_lock_index(s->filename, s->sentence_number); s->sentence_number=idx; if (lidx>=0) active_locks[lidx].sentence_number=idx; pthread_mutex_unlock(&lock_list_mutex); return 0; } idx++; start=i+1; while (content[start]==' ') start++; } }
    return -1;
}
static int commit_session(SentenceSession* s) {
    recalc_current_index_and_update_lock(s);
    FILE* fp=fopen(s->filename, "r"); if(!fp) return -1; char content[MAX_MSG_LEN]; size_t n=fread(content,1,sizeof(content)-1,fp); fclose(fp); content[n]='\0';
    
    // Split working sentence into segments by delimiters (., !, ?)
    // Each delimiter creates a new sentence boundary
    typedef struct { char text[MAX_MSG_LEN]; int has_delim; char delim; } Seg;
    Seg segs[128]; int segc=0;
    {
        const char* p = s->working_sentence; char cur[MAX_MSG_LEN]; int ci=0;
        while (*p) {
            if (*p=='.' || *p=='!' || *p=='?') {
                cur[ci]='\0';
                if (segc < (int)(sizeof(segs)/sizeof(segs[0]))) {
                    char t[MAX_MSG_LEN]; strncpy(t, cur, sizeof(t)); t[sizeof(t)-1]='\0'; trim(t);
                    strncpy(segs[segc].text, t, sizeof(segs[segc].text)); 
                    segs[segc].text[sizeof(segs[segc].text)-1]='\0';
                    segs[segc].has_delim = 1; 
                    segs[segc].delim = *p; 
                    segc++;
                }
                ci=0; p++;
                while (*p==' ' || *p=='\t' || *p=='\n' || *p=='\r') p++;
                continue;
            }
            if (ci < (int)sizeof(cur)-1) cur[ci++] = *p;
            p++;
        }
        cur[ci]='\0';
        // Last segment without delimiter
        if (segc < (int)(sizeof(segs)/sizeof(segs[0]))) {
            char t[MAX_MSG_LEN]; strncpy(t, cur, sizeof(t)); t[sizeof(t)-1]='\0'; trim(t);
            strncpy(segs[segc].text, t, sizeof(segs[segc].text)); 
            segs[segc].text[sizeof(segs[segc].text)-1]='\0';
            segs[segc].has_delim = 0; 
            segs[segc].delim='\0'; 
            segc++;
        }
        if (segc==0) { 
            segs[0].text[0]='\0'; segs[0].has_delim=0; segs[0].delim='\0'; segc=1; 
        }
    }

    int start=0,slen=0; char delim='.'; 
    if (find_sentence_bounds(content, s->sentence_number, &start, &slen, &delim)!=0) {
        // Sentence not found - handle new sentence or incomplete sentence cases
        int scount_now = count_sentences(content);
        if (s->is_new_sentence && s->sentence_number == scount_now) {
            // Append segments as new sentences at end
            char newfile[MAX_MSG_LEN]; 
            strncpy(newfile, content, sizeof(newfile)); 
            newfile[sizeof(newfile)-1]='\0';
            if (strlen(newfile)>0) { 
                char last=newfile[strlen(newfile)-1]; 
                if (!(last==' '||last=='\n')) { 
                    if (strlen(newfile)+1<sizeof(newfile)) strcat(newfile, " "); 
                } 
            }
            for (int i=0;i<segc;i++) {
                if (strlen(segs[i].text)>0) {
                    if (strlen(newfile)+strlen(segs[i].text)>=sizeof(newfile)) return -1;
                    strcat(newfile, segs[i].text);
                }
                if (segs[i].has_delim) { 
                    char dch[2]={segs[i].delim,'\0'}; 
                    if (strlen(newfile)+1>=sizeof(newfile)) return -1; 
                    strcat(newfile, dch); 
                }
                if (i < segc-1 || !segs[i].has_delim) { 
                    if (strlen(newfile)+1>=sizeof(newfile)) return -1; 
                    strcat(newfile, " "); 
                }
            }
            char swapname[MAX_PATH_LEN+16]; snprintf(swapname,sizeof(swapname),"%s.swap", s->filename); 
            FILE* fp2=fopen(swapname,"w"); if(!fp2) return -1; 
            fwrite(newfile,1,strlen(newfile),fp2); fclose(fp2); 
            if (rename(swapname, s->filename)!=0) { remove(swapname); return -1; } 
            return 0;
        }
        // Incomplete sentence cases
        if (!s->is_new_sentence && s->sentence_number==0 && scount_now==0 && strlen(content)>0) {
            // Replace entire content with segments
            char newfile[MAX_MSG_LEN]; newfile[0]='\0';
            for (int i=0;i<segc;i++) {
                if (strlen(segs[i].text)>0) {
                    if (strlen(newfile)+strlen(segs[i].text)>=sizeof(newfile)) return -1;
                    strcat(newfile, segs[i].text);
                }
                if (segs[i].has_delim) { 
                    char dch[2]={segs[i].delim,'\0'}; 
                    if (strlen(newfile)+1>=sizeof(newfile)) return -1; 
                    strcat(newfile, dch); 
                }
                if (i < segc-1) { 
                    if (strlen(newfile)+1>=sizeof(newfile)) return -1; 
                    strcat(newfile, " "); 
                }
            }
            char swapname2[MAX_PATH_LEN+16]; snprintf(swapname2,sizeof(swapname2),"%s.swap", s->filename); 
            FILE* fp3=fopen(swapname2,"w"); if(!fp3) return -1; 
            fwrite(newfile,1,strlen(newfile),fp3); fclose(fp3); 
            if (rename(swapname2, s->filename)!=0) { remove(swapname2); return -1; } 
            return 0;
        }
        if (!s->is_new_sentence && scount_now > 0 && s->sentence_number == scount_now) {
            // Replace trailing incomplete fragment with segments
            int last_delim_pos=-1; 
            for (int i=0; content[i]!='\0'; i++) 
                if (content[i]=='.'||content[i]=='!'||content[i]=='?') last_delim_pos=i;
            int trailing_start = (last_delim_pos>=0)? last_delim_pos+1 : 0; 
            while (content[trailing_start]==' '||content[trailing_start]=='\t') trailing_start++;
            char newfile[MAX_MSG_LEN]; 
            int pLen = trailing_start; 
            if (pLen>(int)strlen(content)) pLen=strlen(content); 
            strncpy(newfile, content, pLen); 
            newfile[pLen]='\0';
            if (strlen(newfile)>0) { 
                char last=newfile[strlen(newfile)-1]; 
                if (!(last==' '||last=='\n')) { 
                    if (strlen(newfile)+1<sizeof(newfile)) strcat(newfile, " "); 
                } 
            }
            for (int i=0;i<segc;i++) {
                if (strlen(segs[i].text)>0) {
                    if (strlen(newfile)+strlen(segs[i].text)>=sizeof(newfile)) return -1;
                    strcat(newfile, segs[i].text);
                }
                if (segs[i].has_delim) { 
                    char dch[2]={segs[i].delim,'\0'}; 
                    if (strlen(newfile)+1>=sizeof(newfile)) return -1; 
                    strcat(newfile, dch); 
                }
                if (i < segc-1) { 
                    if (strlen(newfile)+1>=sizeof(newfile)) return -1; 
                    strcat(newfile, " "); 
                }
            }
            char swapname3[MAX_PATH_LEN+16]; snprintf(swapname3,sizeof(swapname3),"%s.swap", s->filename); 
            FILE* fp4=fopen(swapname3,"w"); if(!fp4) return -1; 
            fwrite(newfile,1,strlen(newfile),fp4); fclose(fp4); 
            if (rename(swapname3, s->filename)!=0) { remove(swapname3); return -1; } 
            return 0;
        }
        return -1;
    }
    
    // Replace existing sentence with segments (first segment replaces, rest are inserted after)
    char newfile[MAX_MSG_LEN]; newfile[0]='\0'; 
    int prefix_len=start; 
    if (prefix_len>(int)strlen(content)) prefix_len=strlen(content); 
    strncat(newfile, content, prefix_len);
    
    // Write all segments
    for (int i=0;i<segc;i++) {
        if (strlen(segs[i].text)>0) {
            if (strlen(newfile)+strlen(segs[i].text)>=sizeof(newfile)) return -1;
            strcat(newfile, segs[i].text);
        }
        if (segs[i].has_delim) { 
            char dch[2]={segs[i].delim,'\0'}; 
            if (strlen(newfile)+1>=sizeof(newfile)) return -1; 
            strcat(newfile, dch); 
        }
        // Add space after each segment except possibly the last
        if (i < segc-1 || !segs[segc-1].has_delim) { 
            if (strlen(newfile)+1>=sizeof(newfile)) return -1; 
            strcat(newfile, " "); 
        }
    }

    // Safety: If original sentence had a delimiter and we somehow lost it (last char not . ! ?), restore it.
    if (segc > 0) {
        char lastc = (strlen(newfile)>0)? newfile[strlen(newfile)-1] : '\0';
        if (!(lastc=='.' || lastc=='!' || lastc=='?')) {
            // Try to use delimiter of last segment if available, else original delimiter
            char restore = '\0';
            if (segc>=1 && segs[segc-1].has_delim) restore = segs[segc-1].delim; else restore = s->original_delim;
            if (restore=='.' || restore=='!' || restore=='?') {
                if (strlen(newfile)+1 < sizeof(newfile)) {
                    newfile[strlen(newfile)] = restore;
                    newfile[strlen(newfile)+1] = '\0';
                }
            }
        }
    }
    
    // Append content AFTER the original sentence (skip original sentence and its delimiter)
    int after = start + slen + 1; // position just after original delimiter
    if ((int)strlen(content) > after) {
        // ensure a separating space if needed
        if (strlen(newfile)>0) {
            char last = newfile[strlen(newfile)-1];
            if (!(last==' '||last=='\n')) { 
                if (strlen(newfile)+1>=sizeof(newfile)) return -1; 
                strcat(newfile, " "); 
            }
        }
        size_t space = sizeof(newfile) - strlen(newfile) - 1; 
        strncat(newfile, content+after, space);
    }
    char swapname[MAX_PATH_LEN+16]; 
    snprintf(swapname,sizeof(swapname),"%s.swap", s->filename); 
    FILE* fp2=fopen(swapname,"w"); if(!fp2) return -1; 
    fwrite(newfile,1,strlen(newfile),fp2); fclose(fp2); 
    if (rename(swapname, s->filename)!=0) { remove(swapname); return -1; } 
    return 0;
}

// --- Public handlers ---
void ss_handle_create_file(int sock) {
    FileRequestPayload payload; memset(&payload, 0, sizeof(payload));
    if (read_all(sock, &payload, sizeof(payload)) == -1) return;
    
    // Create directory structure if needed (mkdir -p style, relative)
    char dir_path[MAX_PATH_LEN];
    strncpy(dir_path, payload.filename, MAX_PATH_LEN);
    char* last_slash = strrchr(dir_path, '/');
    if (last_slash != NULL) { *last_slash = '\0'; mkdirs_recursive(dir_path); }
    
    FILE* fp=fopen(payload.filename, "w"); 
    if(!fp) { 
        // Extra diagnostics to help trace ENOENT issues during testing
        char cwd_buf[PATH_MAX];
        const char* cwd = getcwd(cwd_buf, sizeof(cwd_buf)) ? cwd_buf : "(getcwd failed)";
        LOG_ERROR("Create failure: fopen('%s','w') errno=%d (%s) cwd='%s'", payload.filename, errno, strerror(errno), cwd);
        char err_msg[MAX_MSG_LEN];
        snprintf(err_msg, sizeof(err_msg), "Failed to create file on SS: %s", strerror(errno));
        send_response(sock, MSG_ERROR, err_msg); 
        return; 
    } 
    fclose(fp);
    LOG_INFO("Request: Created file '%s'", payload.filename);
    send_response(sock, MSG_SUCCESS, "File created on SS.");
}
void ss_handle_read_file(int sock) {
    FileRequestPayload req; memset(&req, 0, sizeof(req)); if (read_all(sock, &req, sizeof(req)) == -1) return;
    FILE* fp=fopen(req.filename, "r"); if(!fp) { send_response(sock, MSG_ERROR, "File not found on SS."); return; }
    char content_buffer[MAX_MSG_LEN]={0}; fread(content_buffer,1,MAX_MSG_LEN-1,fp); fclose(fp);
    PacketHeader res_header; SSReadPayload res_payload; res_header.type=MSG_SUCCESS; res_header.size=sizeof(res_payload); strncpy(res_payload.content, content_buffer, MAX_MSG_LEN);
    write_all(sock, &res_header, sizeof(res_header)); write_all(sock, &res_payload, sizeof(res_payload)); LOG_INFO("Request: Sent content of '%s' to client.", req.filename);
}
void ss_handle_write_file(int sock) {
    SSWritePayload payload; memset(&payload,0,sizeof(payload)); if (read_all(sock, &payload, sizeof(payload)) == -1) return;
    
    // Backup file for undo (read old content first)
    char backup_name[MAX_PATH_LEN + 10];
    snprintf(backup_name, sizeof(backup_name), "%s.undo", payload.filename);
    FILE* old_fp = fopen(payload.filename, "r");
    if (old_fp) {
        FILE* backup_fp = fopen(backup_name, "w");
        if (backup_fp) {
            char buf[4096];
            size_t n;
            while ((n = fread(buf, 1, sizeof(buf), old_fp)) > 0) {
                fwrite(buf, 1, n, backup_fp);
            }
            fclose(backup_fp);
        }
        fclose(old_fp);
    }
    
    FILE* fp=fopen(payload.filename, "w"); if(!fp) { send_response(sock, MSG_ERROR, "Failed to open file for writing."); return; }
    fwrite(payload.content,1,strnlen(payload.content,MAX_MSG_LEN),fp); fclose(fp);
    LOG_INFO("Request: Wrote content to '%s'", payload.filename); send_response(sock, MSG_SUCCESS, "File written successfully.");
}
void ss_handle_delete_file(int sock) {
    FileRequestPayload payload; memset(&payload,0,sizeof(payload)); if (read_all(sock, &payload, sizeof(payload)) == -1) return;
    int main_rc = remove(payload.filename);
    // Also remove any undo backup file; ignore error if it doesn't exist
    char backup_name[MAX_PATH_LEN + 10];
    snprintf(backup_name, sizeof(backup_name), "%s.undo", payload.filename);
    (void)remove(backup_name);
    if (main_rc == 0) {
        // Remove any checkpoint snapshot files associated with this file.
        // Pattern: <filename>.ckpt.<tag>
        char work[MAX_PATH_LEN]; strncpy(work, payload.filename, sizeof(work)); work[sizeof(work)-1]='\0';
        char basename[MAX_PATH_LEN]; const char* dirpath = ".";
        char* slash = strrchr(work, '/');
        if (slash) {
            *slash = '\0'; // work now holds directory
            dirpath = work;
            strncpy(basename, slash + 1, sizeof(basename)); basename[sizeof(basename)-1]='\0';
        } else {
            strncpy(basename, work, sizeof(basename)); basename[sizeof(basename)-1]='\0';
        }
        char prefix[MAX_PATH_LEN + 10]; snprintf(prefix, sizeof(prefix), "%s.ckpt.", basename);
        DIR* d = opendir(dirpath);
        if (d) {
            struct dirent* ent; int removed_ckpt = 0;
            while ((ent = readdir(d)) != NULL) {
                if (strncmp(ent->d_name, prefix, strlen(prefix)) == 0) {
                    char fullpath[MAX_PATH_LEN * 2];
                    if (strcmp(dirpath, ".") == 0) snprintf(fullpath, sizeof(fullpath), "%s", ent->d_name);
                    else snprintf(fullpath, sizeof(fullpath), "%s/%s", dirpath, ent->d_name);
                    if (remove(fullpath) == 0) removed_ckpt++;
                }
            }
            closedir(d);
            if (removed_ckpt > 0) {
                LOG_INFO("Cleanup: Removed %d checkpoint snapshots for '%s'", removed_ckpt, payload.filename);
            }
        }
        LOG_INFO("Request: Deleted file '%s' (and cleaned undo if present)", payload.filename);
        send_response(sock, MSG_SUCCESS, "File deleted from SS.");
    } else {
        send_response(sock, MSG_ERROR, "Failed to delete file on SS.");
    }
}
void ss_handle_write_sentence(int sock) {
    SSWriteSentencePayload payload; memset(&payload,0,sizeof(payload)); if (read_all(sock, &payload, sizeof(payload)) == -1) return;
    pthread_mutex_lock(&lock_list_mutex); int idx=find_lock_index(payload.filename, payload.sentence_number);
    if (payload.word_index < 0) { // lock
        if (idx >= 0) {
            // Already locked: allow idempotent success only if same session
            if (strcmp(active_locks[idx].locked_by_user, payload.username)==0 && active_locks[idx].session_id == payload.session_id) {
                pthread_mutex_unlock(&lock_list_mutex); send_response(sock, MSG_SUCCESS, "Lock already held by you."); return;
            }
            pthread_mutex_unlock(&lock_list_mutex); send_response(sock, MSG_ERROR, "Sentence is already locked."); return;
        }
        if (idx < 0) {
            if (num_active_locks >= (int)(sizeof(active_locks)/sizeof(active_locks[0])) || num_sessions >= (int)(sizeof(sessions)/sizeof(sessions[0]))) {
                pthread_mutex_unlock(&lock_list_mutex); send_response(sock, MSG_ERROR, "Too many active locks."); return; }
            SentenceSession sess; pthread_mutex_unlock(&lock_list_mutex);
            if (init_session(payload.filename, payload.sentence_number, payload.username, payload.session_id, &sess)!=0) { send_response(sock, MSG_ERROR, "Sentence index out of range."); return; }
            pthread_mutex_lock(&lock_list_mutex);
            idx = find_lock_index(payload.filename, payload.sentence_number);
            if (idx >= 0) { pthread_mutex_unlock(&lock_list_mutex); send_response(sock, MSG_ERROR, "Race: Sentence got locked by someone else."); return; }
            strncpy(active_locks[num_active_locks].filename, payload.filename, MAX_PATH_LEN);
            active_locks[num_active_locks].sentence_number = sess.sentence_number;
            strncpy(active_locks[num_active_locks].locked_by_user, payload.username, MAX_USERNAME_LEN);
            active_locks[num_active_locks].session_id = payload.session_id;
            sessions[num_sessions] = sess; num_active_locks++; num_sessions++;
        }
        pthread_mutex_unlock(&lock_list_mutex); send_response(sock, MSG_SUCCESS, "Sentence lock acquired."); return;
    } else { // update
        if (idx < 0) { pthread_mutex_unlock(&lock_list_mutex); send_response(sock, MSG_ERROR, "Sentence is not locked."); return; }
        if (!(strcmp(active_locks[idx].locked_by_user, payload.username)==0 && active_locks[idx].session_id == payload.session_id)) { pthread_mutex_unlock(&lock_list_mutex); send_response(sock, MSG_ERROR, "You do not hold the lock for this session."); return; }
        int sidx=find_session_index(payload.filename, payload.sentence_number); if (sidx<0 || sessions[sidx].session_id != payload.session_id) { pthread_mutex_unlock(&lock_list_mutex); send_response(sock, MSG_ERROR, "Internal error: session missing or mismatched."); return; }
        char working[MAX_MSG_LEN]; strncpy(working, sessions[sidx].working_sentence, sizeof(working)); pthread_mutex_unlock(&lock_list_mutex);
    if (apply_word_update(working, payload.word_index, payload.content)!=0) { send_response(sock, MSG_ERROR, "Word index out of range or content too large."); return; }
        pthread_mutex_lock(&lock_list_mutex); strncpy(sessions[sidx].working_sentence, working, MAX_MSG_LEN); pthread_mutex_unlock(&lock_list_mutex);
        recalc_current_index_and_update_lock(&sessions[sidx]);
        send_response(sock, MSG_SUCCESS, "Sentence updated."); return;
    }
}
void ss_handle_etirw(int sock) {
    SimpleFileUserSentencePayload payload; memset(&payload,0,sizeof(payload)); if (read_all(sock, &payload, sizeof(payload)) == -1) return;
    pthread_mutex_lock(&lock_list_mutex); int idx=find_lock_index(payload.filename, payload.sentence_number); if (idx<0 || !(strcmp(active_locks[idx].locked_by_user, payload.username)==0 && active_locks[idx].session_id==payload.session_id)) { pthread_mutex_unlock(&lock_list_mutex); send_response(sock, MSG_ERROR, "No lock held by this session."); return; }
    int sidx=find_session_index(payload.filename, payload.sentence_number); if (sidx<0 || sessions[sidx].session_id != payload.session_id) { pthread_mutex_unlock(&lock_list_mutex); send_response(sock, MSG_ERROR, "Internal error: session missing or mismatched."); return; }
    SentenceSession sess = sessions[sidx]; pthread_mutex_unlock(&lock_list_mutex);
    
    // Backup file for undo before committing
    char backup_name[MAX_PATH_LEN + 10];
    snprintf(backup_name, sizeof(backup_name), "%s.undo", sess.filename);
    FILE* old_fp = fopen(sess.filename, "r");
    if (old_fp) {
        FILE* backup_fp = fopen(backup_name, "w");
        if (backup_fp) {
            char buf[4096];
            size_t n;
            while ((n = fread(buf, 1, sizeof(buf), old_fp)) > 0) {
                fwrite(buf, 1, n, backup_fp);
            }
            fclose(backup_fp);
        }
        fclose(old_fp);
    }
    
    if (commit_session(&sess)!=0) { send_response(sock, MSG_ERROR, "Commit failed."); return; }
    pthread_mutex_lock(&lock_list_mutex); for (int i=idx;i<num_active_locks-1;i++) active_locks[i]=active_locks[i+1]; num_active_locks--; for (int i=sidx;i<num_sessions-1;i++) sessions[i]=sessions[i+1]; num_sessions--; pthread_mutex_unlock(&lock_list_mutex);
    send_response(sock, MSG_SUCCESS, "Sentence committed and lock released.");
}

void ss_handle_undo(int sock) {
    FileRequestPayload payload; 
    memset(&payload, 0, sizeof(payload)); 
    if (read_all(sock, &payload, sizeof(payload)) == -1) return;
    
    // Check if backup exists
    char backup_name[MAX_PATH_LEN + 10];
    snprintf(backup_name, sizeof(backup_name), "%s.undo", payload.filename);
    
    FILE* backup_fp = fopen(backup_name, "r");
    if (!backup_fp) {
        send_response(sock, MSG_ERROR, "No undo history available for this file.");
        return;
    }
    
    // Read backup content
    char backup_content[MAX_MSG_LEN];
    size_t n = fread(backup_content, 1, sizeof(backup_content) - 1, backup_fp);
    backup_content[n] = '\0';
    fclose(backup_fp);
    
    // Restore the backup to the main file
    FILE* fp = fopen(payload.filename, "w");
    if (!fp) {
        send_response(sock, MSG_ERROR, "Failed to restore file.");
        return;
    }
    fwrite(backup_content, 1, n, fp);
    fclose(fp);
    
    // Remove the backup file after undo
    remove(backup_name);
    
    LOG_INFO("Request: Undone last change to '%s'", payload.filename);
    send_response(sock, MSG_SUCCESS, "Undo successful!");
}

void ss_handle_stream_file(int sock) {
    FileRequestPayload req; 
    memset(&req, 0, sizeof(req)); 
    if (read_all(sock, &req, sizeof(req)) == -1) return;
    
    FILE* fp = fopen(req.filename, "r");
    if (!fp) { 
        send_response(sock, MSG_ERROR, "File not found on SS."); 
        return; 
    }
    
    // Read file content
    char content[MAX_MSG_LEN] = {0}; 
    fread(content, 1, MAX_MSG_LEN - 1, fp); 
    fclose(fp);
    
    // Send initial success response indicating stream start
    send_response(sock, MSG_SUCCESS, "STREAM_START");

    // Stream word by word with 0.1 second delay
    char* saveptr = NULL;
    char* word = strtok_r(content, " \t\n\r", &saveptr);
    while (word != NULL) {
        ResponsePayload word_payload; memset(&word_payload, 0, sizeof(word_payload));
        strncpy(word_payload.message, word, MAX_MSG_LEN - 1);
        PacketHeader word_header; word_header.type = MSG_STREAM_WORD; word_header.size = sizeof(word_payload);
        if (write_all(sock, &word_header, sizeof(word_header)) == -1 || write_all(sock, &word_payload, sizeof(word_payload)) == -1) {
            LOG_INFO("Request: Stream connection lost for '%s'", req.filename); return; }
        usleep(100000); // 0.1s pacing
        word = strtok_r(NULL, " \t\n\r", &saveptr);
    }
    // End marker
    ResponsePayload end_payload; memset(&end_payload, 0, sizeof(end_payload)); strncpy(end_payload.message, "STREAM_END", MAX_MSG_LEN-1);
    PacketHeader end_header; end_header.type = MSG_STREAM_END; end_header.size = sizeof(end_payload);
    write_all(sock, &end_header, sizeof(end_header)); write_all(sock, &end_payload, sizeof(end_payload));
    LOG_INFO("Request: Streamed file '%s' to client (end)", req.filename);
}

void ss_handle_exec_file(int sock) {
    FileRequestPayload req; 
    memset(&req, 0, sizeof(req)); 
    if (read_all(sock, &req, sizeof(req)) == -1) return;
    
    FILE* fp = fopen(req.filename, "r");
    if (!fp) { 
        send_response(sock, MSG_ERROR, "File not found on SS."); 
        return; 
    }
    
    // Read file content
    char content[MAX_MSG_LEN] = {0}; 
    size_t bytes_read = fread(content, 1, MAX_MSG_LEN - 1, fp); 
    fclose(fp);
    content[bytes_read] = '\0';
    
    // SECURITY FIX: No longer execute arbitrary shell commands
    // Instead, return the file content for the Name Server to handle safely
    char response[MAX_MSG_LEN];
    snprintf(response, sizeof(response), 
             "SECURITY: Exec forwarded to Name Server for safe handling.\n"
             "File content:\n%s", 
             bytes_read > 0 ? content : "(empty file)");
    
    send_response(sock, MSG_SUCCESS, response);
    LOG_INFO("Request: Exec file '%s' (forwarded to NM for safe execution)", req.filename);
}

// --- Checkpoints ---
static void sanitize_tag(char* out, size_t outsz, const char* tag) {
    size_t j=0; for (size_t i=0; tag[i] && j<outsz-1; i++) {
        unsigned char c=(unsigned char)tag[i];
        if ((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='-'||c=='_'||c=='.') out[j++]=c; else out[j++]='_';
    }
    out[j]='\0';
}
static void build_ckpt_path(char* out, size_t outsz, const char* filename, const char* tag) {
    char safe[64]; sanitize_tag(safe,sizeof(safe),tag);
    snprintf(out, outsz, "%s.ckpt.%s", filename, safe);
}
void ss_handle_checkpoint_create(int sock) {
    CheckpointTagPayload p; memset(&p,0,sizeof(p)); if (read_all(sock,&p,sizeof(p))==-1) return;
    FILE* fp=fopen(p.filename,"r"); if(!fp){ send_response(sock, MSG_ERROR, "File not found on SS."); return; }
    char content[MAX_MSG_LEN]={0}; fread(content,1,MAX_MSG_LEN-1,fp); fclose(fp);
    char path[MAX_PATH_LEN+128]; build_ckpt_path(path,sizeof(path),p.filename,p.tag);
    FILE* cp=fopen(path,"w"); if(!cp){ send_response(sock, MSG_ERROR, "Failed to create checkpoint."); return; }
    fwrite(content,1,strlen(content),cp); fclose(cp);
    char msg[128]; snprintf(msg,sizeof(msg),"Checkpoint saved: %s", p.tag); send_response(sock, MSG_SUCCESS, msg);
}
void ss_handle_checkpoint_view(int sock) {
    CheckpointTagPayload p; memset(&p,0,sizeof(p)); if (read_all(sock,&p,sizeof(p))==-1) return;
    char path[MAX_PATH_LEN+128]; build_ckpt_path(path,sizeof(path),p.filename,p.tag);
    FILE* fp=fopen(path,"r"); if(!fp){ send_response(sock, MSG_ERROR, "Checkpoint not found."); return; }
    char buf[MAX_MSG_LEN]={0}; fread(buf,1,MAX_MSG_LEN-1,fp); fclose(fp);
    ResponsePayload r; memset(&r,0,sizeof(r)); strncpy(r.message, buf, MAX_MSG_LEN-1);
    PacketHeader h={.type=MSG_SUCCESS,.size=sizeof(r)}; write_all(sock,&h,sizeof(h)); write_all(sock,&r,sizeof(r));
}
void ss_handle_checkpoint_revert(int sock) {
    CheckpointTagPayload p; memset(&p,0,sizeof(p)); if (read_all(sock,&p,sizeof(p))==-1) return;
    char path[MAX_PATH_LEN+128]; build_ckpt_path(path,sizeof(path),p.filename,p.tag);
    FILE* cp=fopen(path,"r"); if(!cp){ send_response(sock, MSG_ERROR, "Checkpoint not found."); return; }
    char buf[MAX_MSG_LEN]={0}; size_t n=fread(buf,1,MAX_MSG_LEN-1,cp); fclose(cp);
    // Backup current file
    char backup_name[MAX_PATH_LEN+10]; snprintf(backup_name,sizeof(backup_name),"%s.undo", p.filename);
    FILE* old=fopen(p.filename,"r"); if(old){ FILE* b=fopen(backup_name,"w"); if(b){ char tmp[4096]; size_t m; while((m=fread(tmp,1,sizeof(tmp),old))>0) fwrite(tmp,1,m,b); fclose(b);} fclose(old);}    
    FILE* fp=fopen(p.filename,"w"); if(!fp){ send_response(sock, MSG_ERROR, "Failed to open file for revert."); return; }
    fwrite(buf,1,n,fp); fclose(fp);
    send_response(sock, MSG_SUCCESS, "Reverted to checkpoint.");
}
void ss_handle_checkpoint_list(int sock) {
    CheckpointListPayload p; memset(&p,0,sizeof(p)); if (read_all(sock,&p,sizeof(p))==-1) return;
    // List files that match filename.ckpt.* in current directory
    char prefix[MAX_PATH_LEN+16]; snprintf(prefix,sizeof(prefix),"%s.ckpt.", p.filename);
    size_t plen=strlen(prefix);
    DIR* d=opendir("."); if(!d){ send_response(sock, MSG_ERROR, "Failed to open directory."); return; }
    char out[MAX_MSG_LEN]; out[0]='\0'; int count=0;
    struct dirent* e; while((e=readdir(d))){ if (strncmp(e->d_name, prefix, plen)==0){ const char* tag=e->d_name+plen; char line[96]; snprintf(line,sizeof(line),"%d) %s\n", ++count, tag); if (strlen(out)+strlen(line)+1<sizeof(out)) strcat(out,line); } }
    closedir(d);
    if (out[0]=='\0') strncpy(out,"(no checkpoints)",sizeof(out));
    send_response(sock, MSG_SUCCESS, out);
}

// --- Folders ---
static void mkdirs_recursive(const char* path) {
    if (!path || !*path) return;
    char tmp[MAX_PATH_LEN]; strncpy(tmp, path, sizeof(tmp)); tmp[sizeof(tmp)-1]='\0';
    // Normalize leading './'
    while (strncmp(tmp, "./", 2) == 0) memmove(tmp, tmp+2, strlen(tmp+2)+1);
    // Build relative path incrementally: tok1, tok1/tok2, ...
    char acc[MAX_PATH_LEN] = "";
    char* saveptr=NULL; char* tok=strtok_r(tmp, "/", &saveptr);
    while (tok) {
        if (acc[0] == '\0') {
            strncpy(acc, tok, sizeof(acc)); acc[sizeof(acc)-1]='\0';
        } else {
            size_t need = strlen(acc)+1+strlen(tok)+1; if (need >= sizeof(acc)) break;
            strcat(acc, "/"); strcat(acc, tok);
        }
        mkdir(acc, 0755); // ignore EEXIST
        tok = strtok_r(NULL, "/", &saveptr);
    }
}

void ss_handle_create_folder(int sock) {
    FolderRequestPayload p; memset(&p,0,sizeof(p)); if (read_all(sock,&p,sizeof(p))==-1) return;
    if (p.folder[0]=='\0' || strcmp(p.folder, ".")==0) { send_response(sock, MSG_SUCCESS, "Folder exists."); return; }
    mkdirs_recursive(p.folder);
    // Verify
    struct stat st; if (stat(p.folder,&st)==0 && S_ISDIR(st.st_mode)) send_response(sock, MSG_SUCCESS, "Folder created/exists."); else send_response(sock, MSG_ERROR, "Failed to create folder.");
}

void ss_handle_move_file(int sock) {
    MoveRequestPayload p; memset(&p,0,sizeof(p)); if (read_all(sock,&p,sizeof(p))==-1) return;
    // Ensure destination folder exists
    if (!(p.folder[0]=='\0' || strcmp(p.folder, ".")==0)) mkdirs_recursive(p.folder);
    // Compute basename and source dir
    char work[MAX_PATH_LEN]; strncpy(work, p.filename, sizeof(work)); work[sizeof(work)-1]='\0';
    const char* base = work; char* slash = strrchr(work,'/');
    char srcdir[MAX_PATH_LEN] = ".";
    if (slash) { *slash='\0'; strncpy(srcdir, work, sizeof(srcdir)); srcdir[sizeof(srcdir)-1]='\0'; base = slash+1; }
    // Build destination path
    char dest[MAX_PATH_LEN]; if (p.folder[0]=='\0' || strcmp(p.folder, ".")==0) snprintf(dest,sizeof(dest),"%s", base); else snprintf(dest,sizeof(dest),"%s/%s", p.folder, base);
    // Move main file
    if (rename(p.filename, dest)!=0) { send_response(sock, MSG_ERROR, "Failed to move file."); return; }
    // Move undo backup if any
    {
        char src_undo[MAX_PATH_LEN+10]; snprintf(src_undo,sizeof(src_undo),"%s.undo", dest); // dest.undo (we renamed earlier mistakenly?)
        // We need to move from old undo path
        char old_undo[MAX_PATH_LEN+10]; snprintf(old_undo,sizeof(old_undo),"%s.undo", p.filename);
        // Build dest undo path
        char new_undo[MAX_PATH_LEN+10]; snprintf(new_undo,sizeof(new_undo),"%s.undo", dest);
        (void)rename(old_undo, new_undo); // ignore errors if not exist
        (void)remove(src_undo); // cleanup accidental artifact if any
    }
    // Move checkpoint files: pattern basename.ckpt.* in srcdir
    {
        char prefix[MAX_PATH_LEN+16]; snprintf(prefix,sizeof(prefix),"%s.ckpt.", base);
        DIR* d = opendir(srcdir);
        if (d) {
            struct dirent* e; while ((e=readdir(d))) {
                if (strncmp(e->d_name, prefix, strlen(prefix))==0) {
                    char src[MAX_PATH_LEN*2]; if (strcmp(srcdir, ".")==0) snprintf(src,sizeof(src),"%s", e->d_name); else snprintf(src,sizeof(src),"%s/%s", srcdir, e->d_name);
                    // Destination under dest folder with same ckpt tail
                    const char* tail = e->d_name + strlen(base); // starts with .ckpt.*
                    char dst[MAX_PATH_LEN*2]; if (p.folder[0]=='\0' || strcmp(p.folder, ".")==0) snprintf(dst,sizeof(dst),"%s%s", base, tail); else snprintf(dst,sizeof(dst),"%s/%s%s", p.folder, base, tail);
                    (void)rename(src, dst);
                }
            }
            closedir(d);
        }
    }
    send_response(sock, MSG_SUCCESS, "File moved.");
}

void ss_handle_view_folder(int sock) {
    ViewFolderPayload p; memset(&p,0,sizeof(p)); if (read_all(sock,&p,sizeof(p))==-1) return;
    const char* dir = (p.folder[0]=='\0')?".":p.folder;
    DIR* d = opendir(dir);
    if (!d) { send_response(sock, MSG_ERROR, "Folder not found."); return; }
    char out[MAX_MSG_LEN]; out[0]='\0';
    struct dirent* e; while ((e=readdir(d))) {
        if (e->d_name[0]=='.') continue;
        char fullpath[MAX_PATH_LEN*2];
        if (strcmp(dir, ".")==0) snprintf(fullpath,sizeof(fullpath),"%s", e->d_name); else snprintf(fullpath,sizeof(fullpath),"%s/%s", dir, e->d_name);
        struct stat st; if (stat(fullpath,&st)!=0) continue;
        // Append directories (with trailing '/') and regular files
        if (S_ISDIR(st.st_mode)) {
            char withslash[MAX_PATH_LEN*2]; snprintf(withslash, sizeof(withslash), "%s/", fullpath);
            size_t need = strlen(out)+strlen(withslash)+2; if (need < sizeof(out)) { strcat(out, withslash); strcat(out, "\n"); }
        } else if (S_ISREG(st.st_mode)) {
            size_t need = strlen(out)+strlen(fullpath)+2; if (need < sizeof(out)) { strcat(out, fullpath); strcat(out, "\n"); }
        }
    }
    closedir(d);
    if (out[0]=='\0') strncpy(out, "", sizeof(out));
    send_response(sock, MSG_SUCCESS, out);
}

static int remove_file_and_artifacts(const char* fullpath) {
    // Remove main file
    int rc = remove(fullpath);
    // Remove undo
    char undo[MAX_PATH_LEN+10]; snprintf(undo,sizeof(undo),"%s.undo", fullpath); (void)remove(undo);
    // Remove checkpoints in same dir: basename.ckpt.*
    char work[MAX_PATH_LEN]; strncpy(work, fullpath, sizeof(work)); work[sizeof(work)-1]='\0';
    char basename[MAX_PATH_LEN]; const char* dirpath = "."; char* slash = strrchr(work,'/');
    if (slash) { *slash='\0'; dirpath=work; strncpy(basename, slash+1, sizeof(basename)); basename[sizeof(basename)-1]='\0'; }
    else { strncpy(basename, work, sizeof(basename)); basename[sizeof(basename)-1]='\0'; }
    char prefix[MAX_PATH_LEN+10]; snprintf(prefix,sizeof(prefix),"%s.ckpt.", basename);
    DIR* d = opendir(dirpath); if (d) { struct dirent* e; while ((e=readdir(d))) {
        if (strncmp(e->d_name, prefix, strlen(prefix))==0) {
            char full[MAX_PATH_LEN*2]; if (strcmp(dirpath, ".")==0) snprintf(full,sizeof(full),"%s", e->d_name); else snprintf(full,sizeof(full),"%s/%s", dirpath, e->d_name);
            (void)remove(full);
        }
    } closedir(d);} return rc;
}

void ss_handle_delete_folder(int sock) {
    FolderRequestPayload p; memset(&p,0,sizeof(p)); if (read_all(sock,&p,sizeof(p))==-1) return;
    if (p.folder[0]=='\0' || strcmp(p.folder, ".")==0 || strcmp(p.folder, "/")==0) { send_response(sock, MSG_ERROR, "Cannot delete root folder."); return; }
    // Depth-first delete
    char root[MAX_PATH_LEN]; strncpy(root, p.folder, sizeof(root)); root[sizeof(root)-1]='\0';
    // Normalize trailing '/'
    size_t L=strlen(root); while (L>0 && root[L-1]=='/') { root[L-1]='\0'; L--; }
    // Iterative delete: first files, then dirs bottom-up
    // First pass: delete files recursively
    // Use a simple queue of directories to process; we will collect dirs and delete their files
    // For brevity and portability, fall back to system("find ...") is not allowed. We'll do two-phase traversal.
    // Phase 1: delete files
    {
        // breadth-first traversal collecting directories
        char dirs[1024][MAX_PATH_LEN]; int dcount=0; strncpy(dirs[dcount++], root, MAX_PATH_LEN);
        for (int di=0; di<dcount; di++) {
            DIR* d=opendir(dirs[di]); if (!d) continue; struct dirent* e; char sub[MAX_PATH_LEN*2];
            while ((e=readdir(d))) {
                if (strcmp(e->d_name, ".")==0 || strcmp(e->d_name, "..")==0) continue;
                snprintf(sub,sizeof(sub), "%s/%s", dirs[di], e->d_name); struct stat st; if (stat(sub,&st)!=0) continue;
                if (S_ISDIR(st.st_mode)) { if (dcount<1024) strncpy(dirs[dcount++], sub, MAX_PATH_LEN); }
                else { remove_file_and_artifacts(sub); }
            }
            closedir(d);
        }
        // Phase 2: remove directories in reverse order
        for (int di=dcount-1; di>=0; di--) { (void)rmdir(dirs[di]); }
    }
    send_response(sock, MSG_SUCCESS, "Folder removed.");
}
