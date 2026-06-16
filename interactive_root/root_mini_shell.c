#define _GNU_SOURCE

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

static volatile sig_atomic_t g_interrupted = 0;

struct tokens {
    char **argv;
    size_t argc;
    size_t cap;
};

enum quote_mode {
    QUOTE_NONE = 0,
    QUOTE_SINGLE,
    QUOTE_DOUBLE,
};

static void on_sigint(int signo)
{
    ssize_t ignored;

    (void)signo;
    g_interrupted = 1;
    ignored = write(STDOUT_FILENO, "\n", 1);
    (void)ignored;
}

static void mini_shell_install_signal_handlers(void)
{
    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_sigint;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = SIG_IGN;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGPIPE, &sa, NULL);
}

static void tokens_init(struct tokens *tokens)
{
    tokens->argv = NULL;
    tokens->argc = 0;
    tokens->cap = 0;
}

static void tokens_free(struct tokens *tokens)
{
    size_t i;

    if (tokens == NULL) {
        return;
    }
    for (i = 0; i < tokens->argc; ++i) {
        free(tokens->argv[i]);
    }
    free(tokens->argv);
    tokens_init(tokens);
}

static int tokens_append(struct tokens *tokens, const char *value)
{
    char **new_items;
    char *copy;
    size_t new_cap;

    if (tokens->argc + 1 >= tokens->cap) {
        new_cap = tokens->cap == 0 ? 8 : tokens->cap * 2;
        new_items = (char **)realloc(tokens->argv, new_cap * sizeof(tokens->argv[0]));
        if (new_items == NULL) {
            return -1;
        }
        tokens->argv = new_items;
        tokens->cap = new_cap;
    }

    copy = strdup(value);
    if (copy == NULL) {
        return -1;
    }
    tokens->argv[tokens->argc++] = copy;
    tokens->argv[tokens->argc] = NULL;
    return 0;
}

static int parse_line(const char *line, struct tokens *tokens)
{
    char *token_buf;
    enum quote_mode quote = QUOTE_NONE;
    size_t i;
    size_t token_len = 0;
    int escaped = 0;
    int in_token = 0;

    token_buf = (char *)malloc(strlen(line) + 1);
    if (token_buf == NULL) {
        perror("malloc");
        return -1;
    }

    for (i = 0;; ++i) {
        unsigned char c = (unsigned char)line[i];

        if (escaped) {
            if (c == '\0') {
                fprintf(stderr, "parse: trailing backslash\n");
                free(token_buf);
                return -1;
            }
            token_buf[token_len++] = (char)c;
            escaped = 0;
            in_token = 1;
            continue;
        }

        if (c == '\0') {
            if (quote != QUOTE_NONE) {
                fprintf(stderr, "parse: unmatched quote\n");
                free(token_buf);
                return -1;
            }
            if (in_token) {
                token_buf[token_len] = '\0';
                if (tokens_append(tokens, token_buf) < 0) {
                    perror("strdup");
                    free(token_buf);
                    return -1;
                }
            }
            break;
        }

        if (quote == QUOTE_NONE && isspace(c)) {
            if (in_token) {
                token_buf[token_len] = '\0';
                if (tokens_append(tokens, token_buf) < 0) {
                    perror("strdup");
                    free(token_buf);
                    return -1;
                }
                token_len = 0;
                in_token = 0;
            }
            continue;
        }

        if (quote != QUOTE_SINGLE && c == '\\') {
            escaped = 1;
            in_token = 1;
            continue;
        }

        if (c == '\'' && quote != QUOTE_DOUBLE) {
            in_token = 1;
            quote = (quote == QUOTE_SINGLE) ? QUOTE_NONE : QUOTE_SINGLE;
            continue;
        }

        if (c == '"' && quote != QUOTE_SINGLE) {
            in_token = 1;
            quote = (quote == QUOTE_DOUBLE) ? QUOTE_NONE : QUOTE_DOUBLE;
            continue;
        }

        token_buf[token_len++] = (char)c;
        in_token = 1;
    }

    free(token_buf);
    return 0;
}

static void trim_newline(char *text)
{
    size_t len;

    if (text == NULL) {
        return;
    }
    len = strlen(text);
    while (len > 0 && (text[len - 1] == '\n' || text[len - 1] == '\r')) {
        text[--len] = '\0';
    }
}

static int read_first_line(const char *path, char *buffer, size_t buffer_len)
{
    FILE *fp;

    fp = fopen(path, "r");
    if (fp == NULL) {
        return -1;
    }
    if (fgets(buffer, (int)buffer_len, fp) == NULL) {
        fclose(fp);
        return -1;
    }
    fclose(fp);
    trim_newline(buffer);
    return 0;
}

static void format_mode(mode_t mode, char out[11])
{
    out[0] = S_ISDIR(mode) ? 'd' :
             S_ISLNK(mode) ? 'l' :
             S_ISCHR(mode) ? 'c' :
             S_ISBLK(mode) ? 'b' :
             S_ISSOCK(mode) ? 's' :
             S_ISFIFO(mode) ? 'p' : '-';
    out[1] = (mode & S_IRUSR) ? 'r' : '-';
    out[2] = (mode & S_IWUSR) ? 'w' : '-';
    out[3] = (mode & S_IXUSR) ? 'x' : '-';
    out[4] = (mode & S_IRGRP) ? 'r' : '-';
    out[5] = (mode & S_IWGRP) ? 'w' : '-';
    out[6] = (mode & S_IXGRP) ? 'x' : '-';
    out[7] = (mode & S_IROTH) ? 'r' : '-';
    out[8] = (mode & S_IWOTH) ? 'w' : '-';
    out[9] = (mode & S_IXOTH) ? 'x' : '-';
    out[10] = '\0';
}

static void print_entry(const char *display_name, const char *full_path)
{
    struct stat st;
    char mode[11];

    if (lstat(full_path, &st) < 0) {
        fprintf(stderr, "ls: %s: %s\n", full_path, strerror(errno));
        return;
    }

    format_mode(st.st_mode, mode);
    printf("%s %8ld %s", mode, (long)st.st_size, display_name);
    if (S_ISLNK(st.st_mode)) {
        char target[PATH_MAX];
        ssize_t nread = readlink(full_path, target, sizeof(target) - 1);
        if (nread >= 0) {
            target[nread] = '\0';
            printf(" -> %s", target);
        }
    }
    putchar('\n');
}

static int list_path(const char *path)
{
    struct stat st;

    if (lstat(path, &st) < 0) {
        fprintf(stderr, "ls: %s: %s\n", path, strerror(errno));
        return 1;
    }

    if (!S_ISDIR(st.st_mode)) {
        print_entry(path, path);
        return 0;
    }

    {
        DIR *dir = opendir(path);
        struct dirent *entry;

        if (dir == NULL) {
            fprintf(stderr, "ls: %s: %s\n", path, strerror(errno));
            return 1;
        }

        while ((entry = readdir(dir)) != NULL) {
            char full_path[PATH_MAX];

            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
                continue;
            }

            if (snprintf(full_path, sizeof(full_path), "%s/%s", path, entry->d_name) >= (int)sizeof(full_path)) {
                fprintf(stderr, "ls: path too long: %s/%s\n", path, entry->d_name);
                continue;
            }
            print_entry(entry->d_name, full_path);
        }
        closedir(dir);
    }

    return 0;
}

static int cat_path(const char *path)
{
    FILE *fp;
    char buffer[4096];
    size_t nread;

    fp = fopen(path, "rb");
    if (fp == NULL) {
        fprintf(stderr, "cat: %s: %s\n", path, strerror(errno));
        return 1;
    }

    while ((nread = fread(buffer, 1, sizeof(buffer), fp)) > 0) {
        if (fwrite(buffer, 1, nread, stdout) != nread) {
            fprintf(stderr, "cat: stdout write failed\n");
            fclose(fp);
            return 1;
        }
    }

    if (ferror(fp)) {
        fprintf(stderr, "cat: %s: read failed\n", path);
        fclose(fp);
        return 1;
    }
    fclose(fp);
    return 0;
}

static int write_fd_all(int fd, const void *buffer, size_t buffer_len)
{
    const unsigned char *cursor = (const unsigned char *)buffer;

    while (buffer_len > 0) {
        ssize_t written = write(fd, cursor, buffer_len);
        if (written < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (written == 0) {
            errno = EIO;
            return -1;
        }
        cursor += written;
        buffer_len -= (size_t)written;
    }
    return 0;
}

static int copy_path(const char *source_path, const char *dest_path)
{
    int source_fd;
    int dest_fd;
    struct stat source_stat;
    unsigned char buffer[8192];
    int rc = 0;

    source_fd = open(source_path, O_RDONLY);
    if (source_fd < 0) {
        fprintf(stderr, "cp: %s: %s\n", source_path, strerror(errno));
        return 1;
    }

    if (fstat(source_fd, &source_stat) < 0) {
        fprintf(stderr, "cp: stat %s: %s\n", source_path, strerror(errno));
        close(source_fd);
        return 1;
    }
    if (!S_ISREG(source_stat.st_mode)) {
        fprintf(stderr, "cp: %s: not a regular file\n", source_path);
        close(source_fd);
        return 1;
    }

    dest_fd = open(dest_path, O_WRONLY | O_CREAT | O_TRUNC, source_stat.st_mode & 0777);
    if (dest_fd < 0) {
        fprintf(stderr, "cp: %s: %s\n", dest_path, strerror(errno));
        close(source_fd);
        return 1;
    }

    for (;;) {
        ssize_t nread = read(source_fd, buffer, sizeof(buffer));
        if (nread < 0) {
            if (errno == EINTR) {
                continue;
            }
            fprintf(stderr, "cp: read %s: %s\n", source_path, strerror(errno));
            rc = 1;
            break;
        }
        if (nread == 0) {
            break;
        }
        if (write_fd_all(dest_fd, buffer, (size_t)nread) < 0) {
            fprintf(stderr, "cp: write %s: %s\n", dest_path, strerror(errno));
            rc = 1;
            break;
        }
    }

    if (close(dest_fd) < 0) {
        fprintf(stderr, "cp: close %s: %s\n", dest_path, strerror(errno));
        rc = 1;
    }
    close(source_fd);
    if (rc == 0 && chmod(dest_path, source_stat.st_mode & 0777) < 0) {
        fprintf(stderr, "cp: chmod %s: %s\n", dest_path, strerror(errno));
        rc = 1;
    }
    return rc;
}

static int write_text_path(const char *path, struct tokens *tokens, size_t first_text_index)
{
    int fd;
    size_t i;

    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        fprintf(stderr, "writefile: %s: %s\n", path, strerror(errno));
        return 1;
    }
    if (fchmod(fd, 0644) < 0) {
        fprintf(stderr, "writefile: chmod %s: %s\n", path, strerror(errno));
        close(fd);
        return 1;
    }

    for (i = first_text_index; i < tokens->argc; ++i) {
        if (i > first_text_index && write_fd_all(fd, " ", 1) < 0) {
            fprintf(stderr, "writefile: %s: %s\n", path, strerror(errno));
            close(fd);
            return 1;
        }
        if (write_fd_all(fd, tokens->argv[i], strlen(tokens->argv[i])) < 0) {
            fprintf(stderr, "writefile: %s: %s\n", path, strerror(errno));
            close(fd);
            return 1;
        }
    }
    if (write_fd_all(fd, "\n", 1) < 0) {
        fprintf(stderr, "writefile: %s: %s\n", path, strerror(errno));
        close(fd);
        return 1;
    }
    if (close(fd) < 0) {
        fprintf(stderr, "writefile: close %s: %s\n", path, strerror(errno));
        return 1;
    }
    return 0;
}

static int make_directory_one(const char *path)
{
    struct stat st;

    if (mkdir(path, 0755) == 0) {
        if (chmod(path, 0755) < 0) {
            fprintf(stderr, "mkdir: chmod %s: %s\n", path, strerror(errno));
            return 1;
        }
        return 0;
    }
    if (errno == EEXIST && stat(path, &st) == 0 && S_ISDIR(st.st_mode)) {
        return 0;
    }
    fprintf(stderr, "mkdir: %s: %s\n", path, strerror(errno));
    return 1;
}

static int make_directory_p(const char *path)
{
    char current[PATH_MAX];
    size_t path_len;
    size_t index;

    if (path == NULL || path[0] == '\0') {
        fputs("mkdir: empty path\n", stderr);
        return 1;
    }
    path_len = strlen(path);
    if (path_len >= sizeof(current)) {
        fprintf(stderr, "mkdir: path too long: %s\n", path);
        return 1;
    }

    memcpy(current, path, path_len + 1);
    for (index = 1; current[index] != '\0'; ++index) {
        if (current[index] == '/') {
            current[index] = '\0';
            if (current[0] != '\0' && make_directory_one(current) != 0) {
                return 1;
            }
            current[index] = '/';
        }
    }
    return make_directory_one(current);
}

static int parse_octal_mode(const char *mode_text, mode_t *mode_out)
{
    char *end = NULL;
    long value;

    errno = 0;
    value = strtol(mode_text, &end, 8);
    if (errno != 0 || end == mode_text || *end != '\0' || value < 0 || value > 07777) {
        fprintf(stderr, "chmod: invalid mode: %s\n", mode_text);
        return -1;
    }
    *mode_out = (mode_t)value;
    return 0;
}

static int bind_mount_path(const char *source_path, const char *target_path, unsigned long extra_flags)
{
    if (mount(source_path, target_path, NULL, MS_BIND | extra_flags, NULL) < 0) {
        fprintf(stderr, "bind: %s -> %s: %s\n", source_path, target_path, strerror(errno));
        return 1;
    }
    return 0;
}

static int bind_mount_path_readonly(const char *source_path, const char *target_path)
{
    if (bind_mount_path(source_path, target_path, 0) != 0) {
        return 1;
    }
    if (mount(NULL, target_path, NULL, MS_BIND | MS_REMOUNT | MS_RDONLY, NULL) < 0) {
        fprintf(stderr, "bindro: remount %s read-only: %s\n", target_path, strerror(errno));
        if (umount(target_path) < 0) {
            fprintf(stderr, "bindro: rollback umount %s: %s\n", target_path, strerror(errno));
        }
        return 1;
    }
    return 0;
}

static int mount_tmpfs_path(const char *target_path, const char *options)
{
    const char *mount_options = options != NULL ? options : "size=16m,mode=755";

    if (mount("tmpfs", target_path, "tmpfs", MS_NOSUID | MS_NODEV, mount_options) < 0) {
        fprintf(stderr, "tmpfs: %s: %s\n", target_path, strerror(errno));
        return 1;
    }
    return 0;
}

static int unmount_path(const char *target_path, int lazy)
{
    int flags = lazy ? MNT_DETACH : 0;

    if (umount2(target_path, flags) < 0) {
        fprintf(stderr, "%s: %s: %s\n", lazy ? "umountlazy" : "umount", target_path, strerror(errno));
        return 1;
    }
    return 0;
}

static void print_mount_namespaces(void)
{
    char self_target[PATH_MAX];
    char init_target[PATH_MAX];
    ssize_t self_len;
    ssize_t init_len;

    self_len = readlink("/proc/self/ns/mnt", self_target, sizeof(self_target) - 1);
    init_len = readlink("/proc/1/ns/mnt", init_target, sizeof(init_target) - 1);

    if (self_len >= 0) {
        self_target[self_len] = '\0';
        printf("self: %s\n", self_target);
    } else {
        fprintf(stderr, "mountns: /proc/self/ns/mnt: %s\n", strerror(errno));
    }

    if (init_len >= 0) {
        init_target[init_len] = '\0';
        printf("init: %s\n", init_target);
    } else {
        fprintf(stderr, "mountns: /proc/1/ns/mnt: %s\n", strerror(errno));
    }
}

static int is_numeric_name(const char *name)
{
    size_t i;

    if (name == NULL || name[0] == '\0') {
        return 0;
    }
    for (i = 0; name[i] != '\0'; ++i) {
        if (!isdigit((unsigned char)name[i])) {
            return 0;
        }
    }
    return 1;
}

static void read_proc_cmdline(const char *pid, char *buffer, size_t buffer_len)
{
    char path[PATH_MAX];
    FILE *fp;
    size_t nread;
    size_t i;

    if (snprintf(path, sizeof(path), "/proc/%s/cmdline", pid) >= (int)sizeof(path)) {
        snprintf(buffer, buffer_len, "<path-too-long>");
        return;
    }

    fp = fopen(path, "rb");
    if (fp != NULL) {
        nread = fread(buffer, 1, buffer_len - 1, fp);
        fclose(fp);
        if (nread > 0) {
            for (i = 0; i + 1 < nread; ++i) {
                if (buffer[i] == '\0') {
                    buffer[i] = ' ';
                }
            }
            buffer[nread] = '\0';
            return;
        }
    }

    if (snprintf(path, sizeof(path), "/proc/%s/comm", pid) < (int)sizeof(path) &&
        read_first_line(path, buffer, buffer_len) == 0) {
        return;
    }

    snprintf(buffer, buffer_len, "[%s]", pid);
}

static void print_ps(void)
{
    DIR *dir;
    struct dirent *entry;

    dir = opendir("/proc");
    if (dir == NULL) {
        fprintf(stderr, "ps: /proc: %s\n", strerror(errno));
        return;
    }

    printf("%-6s %-6s %-12s %s\n", "PID", "PPID", "STATE", "CMD");
    while ((entry = readdir(dir)) != NULL) {
        char status_path[PATH_MAX];
        FILE *status_fp;
        char line[256];
        long ppid = -1;
        char state[64] = "?";
        char cmdline[512];

        if (!is_numeric_name(entry->d_name)) {
            continue;
        }

        if (snprintf(status_path, sizeof(status_path), "/proc/%s/status", entry->d_name) >= (int)sizeof(status_path)) {
            continue;
        }
        status_fp = fopen(status_path, "r");
        if (status_fp != NULL) {
            while (fgets(line, sizeof(line), status_fp) != NULL) {
                if (strncmp(line, "PPid:", 5) == 0) {
                    ppid = strtol(line + 5, NULL, 10);
                } else if (strncmp(line, "State:", 6) == 0) {
                    char *p = line + 6;
                    while (*p != '\0' && isspace((unsigned char)*p)) {
                        ++p;
                    }
                    strncpy(state, p, sizeof(state) - 1);
                    state[sizeof(state) - 1] = '\0';
                    trim_newline(state);
                }
            }
            fclose(status_fp);
        }

        read_proc_cmdline(entry->d_name, cmdline, sizeof(cmdline));
        printf("%-6s %-6ld %-12s %s\n", entry->d_name, ppid, state, cmdline);
    }

    closedir(dir);
}

static void print_mounts(void)
{
    (void)cat_path("/proc/mounts");
}

static void print_id(void)
{
    gid_t groups[64];
    int group_count;
    int i;
    char context[256];

    printf("uid=%ld gid=%ld", (long)getuid(), (long)getgid());

    group_count = getgroups((int)(sizeof(groups) / sizeof(groups[0])), groups);
    if (group_count > 0) {
        printf(" groups=");
        for (i = 0; i < group_count; ++i) {
            if (i != 0) {
                putchar(',');
            }
            printf("%ld", (long)groups[i]);
        }
    }

    if (read_first_line("/proc/self/attr/current", context, sizeof(context)) == 0) {
        printf(" context=%s", context);
    }
    putchar('\n');
}

static void print_uname(void)
{
    struct utsname uts;

    if (uname(&uts) < 0) {
        fprintf(stderr, "uname: %s\n", strerror(errno));
        return;
    }
    printf("%s %s %s %s %s\n", uts.sysname, uts.nodename, uts.release, uts.version, uts.machine);
}

static void print_getenforce(void)
{
    char value[16];

    if (read_first_line("/sys/fs/selinux/enforce", value, sizeof(value)) < 0) {
        fprintf(stderr, "getenforce: unavailable\n");
        return;
    }
    if (strcmp(value, "1") == 0) {
        puts("Enforcing");
    } else if (strcmp(value, "0") == 0) {
        puts("Permissive");
    } else {
        printf("%s\n", value);
    }
}

static void print_env(void)
{
    char **env = environ;

    while (env != NULL && *env != NULL) {
        puts(*env);
        ++env;
    }
}

static void print_help(void)
{
    puts("Builtins:");
    puts("  help                 Show this help");
    puts("  pwd                  Print current directory");
    puts("  cd [dir]             Change current directory");
    puts("  ls [path ...]        List files or directory contents");
    puts("  cat <path ...>       Print file contents");
    puts("  cp SRC DST           Copy one regular file");
    puts("  mkdirp PATH [...]    Create directories, including parents");
    puts("  chmod MODE PATH [...] Set octal permissions");
    puts("  writefile PATH TEXT  Write a single text line to a file");
    puts("  echo [args ...]      Print arguments");
    puts("  id                   Show uid, gid, groups, and SELinux context");
    puts("  uname                Show kernel information");
    puts("  ps                   Show a simple process list");
    puts("  mount                Show /proc/mounts");
    puts("  mountns              Show self/init mount namespace ids");
    puts("  bind SRC TARGET      Bind-mount SRC over TARGET");
    puts("  bindro SRC TARGET    Bind-mount SRC over TARGET, then remount read-only");
    puts("  rbind SRC TARGET     Recursive bind-mount SRC over TARGET");
    puts("  tmpfs TARGET [OPTS]  Mount tmpfs at TARGET (default size=16m,mode=755)");
    puts("  umount TARGET        Unmount TARGET");
    puts("  umountlazy TARGET    Lazy-unmount TARGET");
    puts("  getenforce           Show SELinux mode");
    puts("  env                  Print environment variables");
    puts("  set KEY VALUE        Set an environment variable");
    puts("  unset KEY            Remove an environment variable");
    puts("  run CMD [args ...]   Try an external exec (currently blocked here)");
    puts("  clear                Clear the terminal");
    puts("  exit | quit          Leave the shell");
    puts("");
    puts("Note: this install_recovery shell cannot currently exec follow-on binaries.");
}

static void print_prompt(void)
{
    char cwd[PATH_MAX];

    if (getcwd(cwd, sizeof(cwd)) == NULL) {
        snprintf(cwd, sizeof(cwd), "?");
    }
    printf("root@SM-T377A:%s# ", cwd);
    fflush(stdout);
}

static int run_external(struct tokens *tokens)
{
    pid_t child_pid;
    int status;

    child_pid = fork();
    if (child_pid < 0) {
        fprintf(stderr, "run: fork failed: %s\n", strerror(errno));
        return 1;
    }

    if (child_pid == 0) {
        signal(SIGINT, SIG_DFL);
        execvp(tokens->argv[1], &tokens->argv[1]);
        fprintf(stderr, "run: %s: %s\n", tokens->argv[1], strerror(errno));
        _exit(errno == EACCES ? 126 : 127);
    }

    while (waitpid(child_pid, &status, 0) < 0) {
        if (errno != EINTR) {
            fprintf(stderr, "run: waitpid failed: %s\n", strerror(errno));
            return 1;
        }
    }

    if (WIFSIGNALED(status)) {
        fprintf(stderr, "run: child terminated by signal %d\n", WTERMSIG(status));
        return 128 + WTERMSIG(status);
    }
    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }
    return 1;
}

static int dispatch(struct tokens *tokens)
{
    const char *cmd;

    if (tokens->argc == 0) {
        return 0;
    }

    cmd = tokens->argv[0];
    if (strcmp(cmd, "help") == 0) {
        print_help();
        return 0;
    }
    if (strcmp(cmd, "pwd") == 0) {
        char cwd[PATH_MAX];
        if (getcwd(cwd, sizeof(cwd)) == NULL) {
            fprintf(stderr, "pwd: %s\n", strerror(errno));
            return 1;
        }
        puts(cwd);
        return 0;
    }
    if (strcmp(cmd, "cd") == 0) {
        const char *target = tokens->argc >= 2 ? tokens->argv[1] : getenv("HOME");
        if (target == NULL || target[0] == '\0') {
            target = "/";
        }
        if (chdir(target) < 0) {
            fprintf(stderr, "cd: %s: %s\n", target, strerror(errno));
            return 1;
        }
        return 0;
    }
    if (strcmp(cmd, "ls") == 0) {
        size_t i;
        int rc = 0;
        if (tokens->argc == 1) {
            return list_path(".");
        }
        for (i = 1; i < tokens->argc; ++i) {
            if (tokens->argc > 2) {
                printf("%s:\n", tokens->argv[i]);
            }
            if (list_path(tokens->argv[i]) != 0) {
                rc = 1;
            }
            if (tokens->argc > 2 && i + 1 < tokens->argc) {
                putchar('\n');
            }
        }
        return rc;
    }
    if (strcmp(cmd, "cat") == 0) {
        size_t i;
        int rc = 0;
        if (tokens->argc < 2) {
            fputs("cat: missing path\n", stderr);
            return 1;
        }
        for (i = 1; i < tokens->argc; ++i) {
            if (cat_path(tokens->argv[i]) != 0) {
                rc = 1;
            }
        }
        return rc;
    }
    if (strcmp(cmd, "cp") == 0) {
        if (tokens->argc != 3) {
            fputs("cp: usage: cp SRC DST\n", stderr);
            return 1;
        }
        return copy_path(tokens->argv[1], tokens->argv[2]);
    }
    if (strcmp(cmd, "mkdirp") == 0) {
        size_t i;
        int rc = 0;
        if (tokens->argc < 2) {
            fputs("mkdirp: missing path\n", stderr);
            return 1;
        }
        for (i = 1; i < tokens->argc; ++i) {
            if (make_directory_p(tokens->argv[i]) != 0) {
                rc = 1;
            }
        }
        return rc;
    }
    if (strcmp(cmd, "chmod") == 0) {
        size_t i;
        mode_t mode;
        int rc = 0;
        if (tokens->argc < 3) {
            fputs("chmod: usage: chmod MODE PATH [...]\n", stderr);
            return 1;
        }
        if (parse_octal_mode(tokens->argv[1], &mode) < 0) {
            return 1;
        }
        for (i = 2; i < tokens->argc; ++i) {
            if (chmod(tokens->argv[i], mode) < 0) {
                fprintf(stderr, "chmod: %s: %s\n", tokens->argv[i], strerror(errno));
                rc = 1;
            }
        }
        return rc;
    }
    if (strcmp(cmd, "writefile") == 0) {
        if (tokens->argc < 3) {
            fputs("writefile: usage: writefile PATH TEXT\n", stderr);
            return 1;
        }
        return write_text_path(tokens->argv[1], tokens, 2);
    }
    if (strcmp(cmd, "echo") == 0) {
        size_t i;
        for (i = 1; i < tokens->argc; ++i) {
            if (i > 1) {
                putchar(' ');
            }
            fputs(tokens->argv[i], stdout);
        }
        putchar('\n');
        return 0;
    }
    if (strcmp(cmd, "id") == 0) {
        print_id();
        return 0;
    }
    if (strcmp(cmd, "uname") == 0) {
        print_uname();
        return 0;
    }
    if (strcmp(cmd, "ps") == 0) {
        print_ps();
        return 0;
    }
    if (strcmp(cmd, "mount") == 0) {
        print_mounts();
        return 0;
    }
    if (strcmp(cmd, "mountns") == 0) {
        print_mount_namespaces();
        return 0;
    }
    if (strcmp(cmd, "bind") == 0) {
        if (tokens->argc != 3) {
            fputs("bind: usage: bind SRC TARGET\n", stderr);
            return 1;
        }
        return bind_mount_path(tokens->argv[1], tokens->argv[2], 0);
    }
    if (strcmp(cmd, "bindro") == 0) {
        if (tokens->argc != 3) {
            fputs("bindro: usage: bindro SRC TARGET\n", stderr);
            return 1;
        }
        return bind_mount_path_readonly(tokens->argv[1], tokens->argv[2]);
    }
    if (strcmp(cmd, "rbind") == 0) {
        if (tokens->argc != 3) {
            fputs("rbind: usage: rbind SRC TARGET\n", stderr);
            return 1;
        }
        return bind_mount_path(tokens->argv[1], tokens->argv[2], MS_REC);
    }
    if (strcmp(cmd, "tmpfs") == 0) {
        const char *options = NULL;
        if (tokens->argc != 2 && tokens->argc != 3) {
            fputs("tmpfs: usage: tmpfs TARGET [OPTIONS]\n", stderr);
            return 1;
        }
        if (tokens->argc == 3) {
            options = tokens->argv[2];
        }
        return mount_tmpfs_path(tokens->argv[1], options);
    }
    if (strcmp(cmd, "umount") == 0) {
        if (tokens->argc != 2) {
            fputs("umount: usage: umount TARGET\n", stderr);
            return 1;
        }
        return unmount_path(tokens->argv[1], 0);
    }
    if (strcmp(cmd, "umountlazy") == 0) {
        if (tokens->argc != 2) {
            fputs("umountlazy: usage: umountlazy TARGET\n", stderr);
            return 1;
        }
        return unmount_path(tokens->argv[1], 1);
    }
    if (strcmp(cmd, "getenforce") == 0) {
        print_getenforce();
        return 0;
    }
    if (strcmp(cmd, "env") == 0) {
        print_env();
        return 0;
    }
    if (strcmp(cmd, "set") == 0) {
        if (tokens->argc != 3) {
            fputs("set: usage: set KEY VALUE\n", stderr);
            return 1;
        }
        if (setenv(tokens->argv[1], tokens->argv[2], 1) < 0) {
            fprintf(stderr, "set: %s\n", strerror(errno));
            return 1;
        }
        return 0;
    }
    if (strcmp(cmd, "unset") == 0) {
        if (tokens->argc != 2) {
            fputs("unset: usage: unset KEY\n", stderr);
            return 1;
        }
        if (unsetenv(tokens->argv[1]) < 0) {
            fprintf(stderr, "unset: %s\n", strerror(errno));
            return 1;
        }
        return 0;
    }
    if (strcmp(cmd, "clear") == 0) {
        fputs("\033[2J\033[H", stdout);
        return 0;
    }
    if (strcmp(cmd, "run") == 0) {
        if (tokens->argc < 2) {
            fputs("run: missing command\n", stderr);
            return 1;
        }
        return run_external(tokens);
    }
    if (strcmp(cmd, "exit") == 0 || strcmp(cmd, "quit") == 0) {
        return 99;
    }

    fprintf(stderr, "%s: unknown command. Type 'help'.\n", cmd);
    return 1;
}

int mini_shell_handle_leaf_mode(int argc, char **argv, const char *marker)
{
    if (argc >= 2 && strcmp(argv[1], "--leaf") == 0) {
        printf("%s %s\n", marker, argc >= 3 ? argv[2] : "OK");
        return 1;
    }
    return 0;
}

int mini_shell_run(void)
{
    char line[4096];

    mini_shell_install_signal_handlers();
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    puts("[+] Mini root shell ready. Type 'help' for builtins.");
    print_id();

    for (;;) {
        struct tokens tokens;
        int rc;

        g_interrupted = 0;
        print_prompt();
        if (fgets(line, sizeof(line), stdin) == NULL) {
            if (g_interrupted || errno == EINTR) {
                clearerr(stdin);
                continue;
            }
            putchar('\n');
            break;
        }

        trim_newline(line);
        tokens_init(&tokens);
        if (parse_line(line, &tokens) < 0) {
            tokens_free(&tokens);
            continue;
        }
        rc = dispatch(&tokens);
        tokens_free(&tokens);
        if (rc == 99) {
            break;
        }
    }

    return 0;
}

#ifndef MINI_SHELL_EMBEDDED
int main(int argc, char **argv)
{
    if (mini_shell_handle_leaf_mode(argc, argv, "ROOT_MINI_SHELL_LEAF")) {
        return 0;
    }
    return mini_shell_run();
}
#endif
