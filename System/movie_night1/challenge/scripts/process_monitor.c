/*
 * Process monitor that tracks and kills processes belonging to a specific UID
 * ONLY if their parent process is not authorized (not root and not the user itself).
 * * Modified to remove execution time limits.
 */

 #define _GNU_SOURCE
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <unistd.h>
 #include <sys/types.h>
 #include <sys/stat.h>
 #include <fcntl.h>
 #include <dirent.h>
 #include <signal.h>
 #include <time.h>
 #include <errno.h>
 #include <stdarg.h>
 
 #define DBUS_SERVICE_UID 1005
 #define LOG_FILE "/root/process-monitor.log"
 #define BUFFER_SIZE 4096
 
 static FILE *log_file = NULL;
 
 void log_message(const char *level, const char *format, ...) {
     va_list args;
     va_start(args, format);
     
     time_t now = time(NULL);
     char time_str[64];
     struct tm *tm_info = localtime(&now);
     strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);
     
     if (log_file) {
         fprintf(log_file, "[%s] %s: ", time_str, level);
         vfprintf(log_file, format, args);
         fprintf(log_file, "\n");
         fflush(log_file);
     }
     
     va_end(args);
 }
 
 int get_process_uid_fast(pid_t pid, uid_t *uid, uid_t *euid) {
     char path[256];
     FILE *f;
     char line[256];
     
     snprintf(path, sizeof(path), "/proc/%d/status", pid);
     f = fopen(path, "r");
     if (!f) {
         return -1;
     }
     
     while (fgets(line, sizeof(line), f)) {
         if (strncmp(line, "Uid:", 4) == 0) {
             sscanf(line, "Uid:\t%u\t%u", uid, euid);
             fclose(f);
             return 0;
         }
     }
     
     fclose(f);
     return -1;
 }
 
 // Simplified to only get name for logging, as we no longer need starttime
 int get_process_name(pid_t pid, char *exe_name, size_t exe_name_len) {
     char path[256];
     
     // Get exe name
     snprintf(path, sizeof(path), "/proc/%d/exe", pid);
     ssize_t len = readlink(path, exe_name, exe_name_len - 1);
     if (len > 0) {
         exe_name[len] = '\0';
         // Get basename
         char *basename = strrchr(exe_name, '/');
         if (basename) {
             memmove(exe_name, basename + 1, strlen(basename));
         }
     } else {
         // Fallback to reading cmdline if readlink fails or is empty
         snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
         FILE *f = fopen(path, "rb");
         if (f) {
             size_t n = fread(exe_name, 1, exe_name_len - 1, f);
             fclose(f);
             if (n > 0) {
                 exe_name[n] = '\0';
             } else {
                 return -1;
             }
         } else {
             return -1;
         }
     }
     
     return 0;
 }
 
 uid_t get_parent_uid(pid_t pid) {
     char path[256];
     FILE *f;
     char line[BUFFER_SIZE];
     char *p;
     pid_t ppid = 0;
     
     snprintf(path, sizeof(path), "/proc/%d/stat", pid);
     f = fopen(path, "r");
     if (!f) {
         return -1;
     }
     
     if (fgets(line, sizeof(line), f)) {
         // Find the closing parenthesis of the process name
         p = strchr(line, ')');
         if (!p) {
             fclose(f);
             return -1;
         }
         p++; // Move past ')'
         
         // Skip whitespace and state (field 3)
         while (*p == ' ' || *p == '\t') p++;
         while (*p && *p != ' ' && *p != '\t') p++; // Skip state
         while (*p == ' ' || *p == '\t') p++;
         
         // Now we're at ppid (field 4)
         if (*p) {
             ppid = atoi(p);
         }
     }
     fclose(f);
     
     if (ppid == 0) {
         return -1; // Error or init
     }
     
     uid_t uid, euid;
     if (get_process_uid_fast(ppid, &uid, &euid) == 0) {
         return uid;
     }
     
     return -1;
 }
 
 void send_message_to_users(const char *message) {
     DIR *dir = opendir("/dev/pts");
     if (!dir) {
         return;
     }
     
     struct dirent *entry;
     while ((entry = readdir(dir)) != NULL) {
         if (entry->d_name[0] >= '0' && entry->d_name[0] <= '9') {
             char path[256];
             snprintf(path, sizeof(path), "/dev/pts/%s", entry->d_name);
             
             int fd = open(path, O_WRONLY | O_NONBLOCK);
             if (fd >= 0) {
                 write(fd, message, strlen(message));
                 close(fd);
             }
         }
     }
     closedir(dir);
 }
 
 int kill_process(pid_t pid, const char *proc_name, const char *reason) {
     // Kill first for maximum speed
     if (kill(pid, SIGKILL) != 0) {
         // Check if process is already gone
         if (errno == ESRCH) return 0;
         return -1;
     }
     
     log_message("WARNING", "Killed process %d (%s): %s", pid, proc_name, reason);
     
     // Send wall message after killing (non-blocking)
     const char *wall_msg = 
         "\n"
         "*** SECURITY ALERT ***\n"
         "\n"
         "Hardening measures prevent the dbus-service user from executing\n"
         "commands outside of the dbus context. Unauthorized process execution\n"
         "has been blocked.\n"
         "\n";
     
     send_message_to_users(wall_msg);
     
     return 0;
 }
 
 void monitor_processes(void) {
     log_message("INFO", "Process monitor started, monitoring dbus-service user (UID %d)", DBUS_SERVICE_UID);
     log_message("INFO", "Policy: Kill %d processes if parent is not root(0) or self(%d)", DBUS_SERVICE_UID, DBUS_SERVICE_UID);
     
     while (1) {
         // Get all running process IDs
         DIR *proc_dir = opendir("/proc");
         if (!proc_dir) {
             usleep(100000);
             continue;
         }
         
         struct dirent *entry;
         while ((entry = readdir(proc_dir)) != NULL) {
             if (entry->d_name[0] < '0' || entry->d_name[0] > '9') {
                 continue;
             }
             
             pid_t pid = atoi(entry->d_name);
             if (pid <= 0) {
                 continue;
             }
             
             // 1. Check UID of the process
             uid_t uid, euid;
             if (get_process_uid_fast(pid, &uid, &euid) != 0) {
                 continue;
             }
             
             // Only interested in DBUS_SERVICE_UID
             if (uid != DBUS_SERVICE_UID && euid != DBUS_SERVICE_UID) {
                 continue;
             }
             
             // 2. Check Parent UID
             uid_t parent_uid = get_parent_uid(pid);
             
             // The constraint: Parent must be Root OR Parent must be the user itself (1005)
             // If Parent is NEITHER, we kill.
             if (parent_uid != 0 && parent_uid != DBUS_SERVICE_UID) {
                 char exe_name[256] = "unknown";
                 get_process_name(pid, exe_name, sizeof(exe_name));
                 
                 char reason[64];
                 snprintf(reason, sizeof(reason), "Unauthorized parent UID: %d", parent_uid);
                 
                 kill_process(pid, exe_name, reason);
             }
         }
         
         closedir(proc_dir);
         
         usleep(1000); 
     }
 }
 
 int main(void) {
     if (geteuid() != 0) {
         fprintf(stderr, "Error: process_monitor must be run as root\n");
         return 1;
     }
     
     // Open log file
     log_file = fopen(LOG_FILE, "a");
     if (!log_file) {
         fprintf(stderr, "Error: could not open log file %s: %s\n", LOG_FILE, strerror(errno));
         return 1;
     }
     
     monitor_processes();
     
     if (log_file) fclose(log_file);
     return 0;
 }