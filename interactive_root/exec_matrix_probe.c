#define _GNU_SOURCE

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static int run_case_fork(const char *name, char *const argv[])
{
    int pipefd[2];
    pid_t child_pid;
    int status;
    char buffer[1024];
    ssize_t nread;

    printf("=== %s ===\n", name);
    if (pipe(pipefd) < 0) {
        printf("pipe failed: %s\n", strerror(errno));
        return 1;
    }

    child_pid = fork();
    if (child_pid < 0) {
        printf("fork failed: %s\n", strerror(errno));
        close(pipefd[0]);
        close(pipefd[1]);
        return 1;
    }

    if (child_pid == 0) {
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[0]);
        close(pipefd[1]);
        execv(argv[0], argv);
        printf("EXEC_FAIL errno=%d (%s)\n", errno, strerror(errno));
        _exit(111);
    }

    close(pipefd[1]);
    while ((nread = read(pipefd[0], buffer, sizeof(buffer) - 1)) > 0) {
        buffer[nread] = '\0';
        fputs(buffer, stdout);
    }
    close(pipefd[0]);

    while (waitpid(child_pid, &status, 0) < 0) {
        if (errno != EINTR) {
            printf("waitpid failed: %s\n", strerror(errno));
            return 1;
        }
    }

    if (WIFEXITED(status)) {
        printf("exit=%d\n", WEXITSTATUS(status));
    } else if (WIFSIGNALED(status)) {
        printf("signal=%d\n", WTERMSIG(status));
    } else {
        puts("exit=unknown");
    }
    putchar('\n');
    return 0;
}

static int run_case_vfork(const char *name, char *const argv[])
{
    int pipefd[2];
    pid_t child_pid;
    int status;
    char buffer[1024];
    ssize_t nread;

    printf("=== %s ===\n", name);
    if (pipe(pipefd) < 0) {
        printf("pipe failed: %s\n", strerror(errno));
        return 1;
    }

    child_pid = vfork();
    if (child_pid < 0) {
        printf("vfork failed: %s\n", strerror(errno));
        close(pipefd[0]);
        close(pipefd[1]);
        return 1;
    }

    if (child_pid == 0) {
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[0]);
        close(pipefd[1]);
        execv(argv[0], argv);
        printf("EXEC_FAIL errno=%d (%s)\n", errno, strerror(errno));
        _exit(111);
    }

    close(pipefd[1]);
    while ((nread = read(pipefd[0], buffer, sizeof(buffer) - 1)) > 0) {
        buffer[nread] = '\0';
        fputs(buffer, stdout);
    }
    close(pipefd[0]);

    while (waitpid(child_pid, &status, 0) < 0) {
        if (errno != EINTR) {
            printf("waitpid failed: %s\n", strerror(errno));
            return 1;
        }
    }

    if (WIFEXITED(status)) {
        printf("exit=%d\n", WEXITSTATUS(status));
    } else if (WIFSIGNALED(status)) {
        printf("signal=%d\n", WTERMSIG(status));
    } else {
        puts("exit=unknown");
    }
    putchar('\n');
    return 0;
}

static void print_context(void)
{
    FILE *fp;
    char line[256];

    printf("uid=%ld gid=%ld\n", (long)getuid(), (long)getgid());
    fp = fopen("/proc/self/attr/current", "r");
    if (fp != NULL) {
        if (fgets(line, sizeof(line), fp) != NULL) {
            size_t len = strlen(line);
            while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
                line[--len] = '\0';
            }
            printf("context=%s\n", line);
        }
        fclose(fp);
    }
    putchar('\n');
}

int main(int argc, char **argv)
{
    char *system_sh[] = { "/system/bin/sh", "-c", "echo SYSTEM_SH_OK", NULL };
    char *system_toolbox[] = { "/system/bin/toolbox", "echo", "SYSTEM_TOOLBOX_OK", NULL };
    char *system_toybox[] = { "/system/bin/toybox", "echo", "SYSTEM_TOYBOX_OK", NULL };
    char *copied_sh[] = { "/data/local/tmp/root_shell_copy", "-c", "echo ROOT_COPY_OK", NULL };
    char *tmp_toybox[] = { "/data/local/tmp/toybin/toybox", "echo", "TMP_TOYBOX_OK", NULL };
    char *mini_shell_leaf[] = { "/data/local/tmp/root_mini_shell", "--leaf", "MINI_SHELL_OK", NULL };

    if (argc >= 2 && strcmp(argv[1], "--leaf") == 0) {
        printf("EXEC_MATRIX_LEAF %s\n", argc >= 3 ? argv[2] : "OK");
        return 0;
    }

    signal(SIGPIPE, SIG_IGN);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    puts("[+] exec-matrix probe");
    print_context();

    puts("[+] fork() exec tests");
    run_case_fork("fork:system-sh", system_sh);
    run_case_fork("fork:system-toolbox", system_toolbox);
    run_case_fork("fork:system-toybox", system_toybox);
    run_case_fork("fork:copied-root-shell", copied_sh);
    run_case_fork("fork:tmp-toybox", tmp_toybox);
    run_case_fork("fork:mini-shell-leaf", mini_shell_leaf);

    puts("[+] vfork() exec tests");
    run_case_vfork("vfork:system-sh", system_sh);
    run_case_vfork("vfork:system-toolbox", system_toolbox);
    run_case_vfork("vfork:system-toybox", system_toybox);
    run_case_vfork("vfork:copied-root-shell", copied_sh);
    run_case_vfork("vfork:tmp-toybox", tmp_toybox);
    run_case_vfork("vfork:mini-shell-leaf", mini_shell_leaf);
    return 0;
}
