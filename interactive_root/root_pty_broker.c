#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#define MINI_SHELL_EMBEDDED
#include "root_mini_shell.c"

static volatile sig_atomic_t g_stop = 0;
static int g_listen_fd = -1;
static char g_socket_path[sizeof(((struct sockaddr_un *)0)->sun_path)];

static void request_stop(int signo)
{
    (void)signo;
    g_stop = 1;
}

static void cleanup_socket(void)
{
    if (g_listen_fd >= 0) {
        close(g_listen_fd);
        g_listen_fd = -1;
    }
    if (g_socket_path[0] != '\0') {
        unlink(g_socket_path);
    }
}

static void usage(const char *prog)
{
    fprintf(stderr, "Usage: %s --socket <path> [--shell <path>]\n", prog);
}

static int write_all(int fd, const void *buf, size_t len)
{
    const unsigned char *p = (const unsigned char *)buf;
    while (len > 0) {
        ssize_t written = write(fd, p, len);
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
        p += written;
        len -= (size_t)written;
    }
    return 0;
}

static int create_listener(const char *socket_path)
{
    struct sockaddr_un addr;
    mode_t old_umask;
    int fd;

    if (strlen(socket_path) >= sizeof(addr.sun_path)) {
        errno = ENAMETOOLONG;
        return -1;
    }

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    memcpy(addr.sun_path, socket_path, strlen(socket_path) + 1);

    unlink(socket_path);
    old_umask = umask(0111);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        umask(old_umask);
        close(fd);
        return -1;
    }
    umask(old_umask);

    if (listen(fd, 4) < 0) {
        close(fd);
        unlink(socket_path);
        return -1;
    }

    return fd;
}

static int open_pty_master(int *master_fd_out, char *slave_name, size_t slave_name_len)
{
    int master_fd;

    master_fd = posix_openpt(O_RDWR | O_NOCTTY);
    if (master_fd < 0) {
        return -1;
    }
    if (grantpt(master_fd) < 0 || unlockpt(master_fd) < 0) {
        close(master_fd);
        return -1;
    }
    if (ptsname_r(master_fd, slave_name, slave_name_len) != 0) {
        close(master_fd);
        return -1;
    }

    *master_fd_out = master_fd;
    return 0;
}

static void child_error(const char *stage, const char *detail)
{
    if (detail != NULL) {
        dprintf(STDERR_FILENO, "[broker-child] %s (%s): %s\n", stage, detail, strerror(errno));
    } else {
        dprintf(STDERR_FILENO, "[broker-child] %s: %s\n", stage, strerror(errno));
    }
}

static int spawn_shell(const char *shell_path, int *master_fd_out, pid_t *child_pid_out)
{
    char slave_name[128];
    int master_fd = -1;
    pid_t child_pid;

    if (open_pty_master(&master_fd, slave_name, sizeof(slave_name)) < 0) {
        return -1;
    }

    child_pid = fork();
    if (child_pid < 0) {
        close(master_fd);
        return -1;
    }

    if (child_pid == 0) {
        int slave_fd;

        if (setsid() < 0) {
            _exit(126);
        }

        slave_fd = open(slave_name, O_RDWR);
        if (slave_fd < 0) {
            _exit(126);
        }
        /*
         * Opening the PTY slave after setsid() is usually enough to make it the
         * controlling terminal. Some Android builds still reject TIOCSCTTY here
         * even though the PTY is otherwise usable, so treat it as best-effort.
         */
        (void)ioctl(slave_fd, TIOCSCTTY, 0);
        if (dup2(slave_fd, STDIN_FILENO) < 0 ||
            dup2(slave_fd, STDOUT_FILENO) < 0 ||
            dup2(slave_fd, STDERR_FILENO) < 0) {
            _exit(126);
        }
        if (slave_fd > STDERR_FILENO) {
            close(slave_fd);
        }
        close(master_fd);
        if (chdir("/") < 0) {
            child_error("chdir", "/");
            _exit(126);
        }
        setenv("PATH", "/sbin:/vendor/bin:/system/sbin:/system/bin:/system/xbin:/data/local/tmp:/data/local/tmp/toybin", 1);
        setenv("PS1", "root@SM-T377A:/# ", 1);
        setenv("HOME", "/data/local/tmp", 1);
        setenv("TERM", "vt100", 1);
        setenv("SHELL", shell_path, 1);
        if (strcmp(shell_path, "/data/local/tmp/root_mini_shell") == 0 ||
            strcmp(shell_path, "builtin:minishell") == 0) {
            _exit(mini_shell_run());
        }
        execl(shell_path, shell_path, (char *)NULL);
        child_error("exec", shell_path);
        _exit(127);
    }

    *master_fd_out = master_fd;
    *child_pid_out = child_pid;
    return 0;
}

static void reap_child(pid_t child_pid)
{
    int status;
    int i;

    if (child_pid <= 0) {
        return;
    }

    if (waitpid(child_pid, &status, WNOHANG) == child_pid) {
        return;
    }

    kill(child_pid, SIGHUP);
    for (i = 0; i < 20; ++i) {
        pid_t rc = waitpid(child_pid, &status, WNOHANG);
        if (rc == child_pid) {
            return;
        }
        if (rc < 0 && errno != EINTR) {
            return;
        }
        usleep(100000);
    }

    kill(child_pid, SIGTERM);
    for (i = 0; i < 20; ++i) {
        pid_t rc = waitpid(child_pid, &status, WNOHANG);
        if (rc == child_pid) {
            return;
        }
        if (rc < 0 && errno != EINTR) {
            return;
        }
        usleep(100000);
    }

    kill(child_pid, SIGKILL);
    while (waitpid(child_pid, &status, 0) < 0) {
        if (errno != EINTR) {
            break;
        }
    }
}

static int relay_loop(int client_fd, int pty_fd)
{
    unsigned char buffer[4096];

    for (;;) {
        struct pollfd pfds[2];
        int poll_rc;

        if (g_stop) {
            errno = EINTR;
            return -1;
        }

        pfds[0].fd = client_fd;
        pfds[0].events = POLLIN | POLLERR | POLLHUP;
        pfds[0].revents = 0;
        pfds[1].fd = pty_fd;
        pfds[1].events = POLLIN | POLLERR | POLLHUP;
        pfds[1].revents = 0;

        poll_rc = poll(pfds, 2, -1);
        if (poll_rc < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }

        if (pfds[0].revents & POLLIN) {
            ssize_t nread = read(client_fd, buffer, sizeof(buffer));
            if (nread < 0) {
                if (errno == EINTR) {
                    continue;
                }
                return -1;
            }
            if (nread == 0) {
                return 0;
            }
            if (write_all(pty_fd, buffer, (size_t)nread) < 0) {
                return -1;
            }
        }

        if (pfds[1].revents & POLLIN) {
            ssize_t nread = read(pty_fd, buffer, sizeof(buffer));
            if (nread < 0) {
                if (errno == EINTR) {
                    continue;
                }
                return -1;
            }
            if (nread == 0) {
                return 0;
            }
            if (write_all(client_fd, buffer, (size_t)nread) < 0) {
                return -1;
            }
        }

        if (pfds[0].revents & (POLLERR | POLLHUP)) {
            return 0;
        }
        if (pfds[1].revents & (POLLERR | POLLHUP)) {
            return 0;
        }
    }
}

static int handle_shell_session(int client_fd, const char *shell_path)
{
    int master_fd = -1;
    pid_t child_pid = -1;

    if (spawn_shell(shell_path, &master_fd, &child_pid) < 0) {
        static const char err_msg[] = "ERR shell\n";
        (void)write_all(client_fd, err_msg, sizeof(err_msg) - 1);
        return -1;
    }

    (void)relay_loop(client_fd, master_fd);
    close(master_fd);
    reap_child(child_pid);
    return 0;
}

static int handle_client(int client_fd, const char *shell_path, int *exit_requested)
{
    unsigned char op = 0;
    ssize_t nread;

    *exit_requested = 0;
    do {
        nread = read(client_fd, &op, 1);
    } while (nread < 0 && errno == EINTR);

    if (nread <= 0) {
        return -1;
    }

    switch (op) {
    case 'P':
    {
        static const char pong[] = "PONG\n";
        return write_all(client_fd, pong, sizeof(pong) - 1);
    }
    case 'S':
        return handle_shell_session(client_fd, shell_path);
    case 'X':
    {
        static const char bye[] = "BYE\n";
        *exit_requested = 1;
        return write_all(client_fd, bye, sizeof(bye) - 1);
    }
    default:
    {
        static const char err_msg[] = "ERR unknown\n";
        return write_all(client_fd, err_msg, sizeof(err_msg) - 1);
    }
    }
}

static int install_signal_handlers(void)
{
    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = request_stop;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGINT, &sa, NULL) < 0 ||
        sigaction(SIGTERM, &sa, NULL) < 0 ||
        sigaction(SIGHUP, &sa, NULL) < 0) {
        return -1;
    }

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = SIG_IGN;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGPIPE, &sa, NULL) < 0) {
        return -1;
    }

    return 0;
}

int main(int argc, char **argv)
{
    const char *socket_path = NULL;
    const char *shell_path = "/data/local/tmp/root_mini_shell";
    int i;

    for (i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--socket") == 0) {
            if (++i >= argc) {
                usage(argv[0]);
                return EXIT_FAILURE;
            }
            socket_path = argv[i];
        } else if (strcmp(argv[i], "--shell") == 0) {
            if (++i >= argc) {
                usage(argv[0]);
                return EXIT_FAILURE;
            }
            shell_path = argv[i];
        } else {
            usage(argv[0]);
            return EXIT_FAILURE;
        }
    }

    if (socket_path == NULL) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }
    if (strlen(socket_path) >= sizeof(g_socket_path)) {
        fprintf(stderr, "Socket path too long: %s\n", socket_path);
        return EXIT_FAILURE;
    }

    memcpy(g_socket_path, socket_path, strlen(socket_path) + 1);
    atexit(cleanup_socket);

    if (install_signal_handlers() < 0) {
        perror("sigaction");
        return EXIT_FAILURE;
    }

    g_listen_fd = create_listener(socket_path);
    if (g_listen_fd < 0) {
        perror("socket setup");
        return EXIT_FAILURE;
    }

    while (!g_stop) {
        int client_fd;
        int exit_requested = 0;

        client_fd = accept(g_listen_fd, NULL, NULL);
        if (client_fd < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (!g_stop) {
                perror("accept");
            }
            break;
        }

        if (handle_client(client_fd, shell_path, &exit_requested) < 0 && !g_stop) {
            perror("client");
        }
        close(client_fd);

        if (exit_requested) {
            break;
        }
    }

    cleanup_socket();
    return EXIT_SUCCESS;
}
