#define _GNU_SOURCE

#include <errno.h>
#include <grp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static void fail(const char *operation) {
    fprintf(stderr, "su: %s failed: %s\n", operation, strerror(errno));
    _exit(1);
}

int main(int argc, char **argv) {
    fprintf(
        stderr,
        "before fork: uid=%u euid=%u gid=%u egid=%u\n",
        getuid(), geteuid(), getgid(), getegid()
    );

    pid_t pid = fork();

    if (pid < 0) {
        fail("fork");
    }

    if (pid > 0) {
        int status = 0;

        if (waitpid(pid, &status, 0) < 0) {
            fail("waitpid");
        }

        if (WIFEXITED(status)) {
            return WEXITSTATUS(status);
        }

        if (WIFSIGNALED(status)) {
            return 128 + WTERMSIG(status);
        }

        return 1;
    }

    /* Child process */
    fprintf(
        stderr,
        "after fork: uid=%u euid=%u gid=%u egid=%u\n",
        getuid(), geteuid(), getgid(), getegid()
    );

    if (setgroups(0, NULL) == -1) {
        fail("setgroups");
    }

    if (setresgid(0, 0, 0) == -1) {
        fail("setresgid");
    }

    if (setresuid(0, 0, 0) == -1) {
        fail("setresuid");
    }

    fprintf(
        stderr,
        "after transition: uid=%u euid=%u gid=%u egid=%u\n",
        getuid(), geteuid(), getgid(), getegid()
    );

    setenv("HOME", "/data/local/tmp", 1);
    setenv("USER", "root", 1);
    setenv("LOGNAME", "root", 1);
    setenv("PATH", "/system/bin:/system/xbin:/vendor/bin", 1);

    if (argc >= 3 && strcmp(argv[1], "-c") == 0) {
        execl("/system/bin/sh", "sh", "-c", argv[2], NULL);
        fail("exec command");
    }

    if (argc > 1) {
        execvp(argv[1], &argv[1]);
        fail("execvp");
    }

    execl("/system/bin/sh", "sh", NULL);
    fail("exec shell");
}
