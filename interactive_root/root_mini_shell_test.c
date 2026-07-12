#define _GNU_SOURCE
#define MINI_SHELL_EMBEDDED

#include "root_mini_shell.c"

#include <stdarg.h>
#include <stdint.h>

static int g_failures;

static void check_impl(int condition, const char *file, int line, const char *format, ...)
{
    va_list args;

    if (condition) {
        return;
    }

    ++g_failures;
    fprintf(stderr, "%s:%d: ", file, line);
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
    fputc('\n', stderr);
}

#define CHECK(condition, ...) \
    check_impl((condition), __FILE__, __LINE__, __VA_ARGS__)

struct captured_output {
    char *stdout_text;
    char *stderr_text;
};

static int set_close_on_exec(int descriptor)
{
    int flags;

    flags = fcntl(descriptor, F_GETFD);
    if (flags < 0) {
        return -1;
    }
    if (fcntl(descriptor, F_SETFD, flags | FD_CLOEXEC) < 0) {
        return -1;
    }
    return 0;
}

static void captured_output_init(struct captured_output *output)
{
    output->stdout_text = NULL;
    output->stderr_text = NULL;
}

static void captured_output_free(struct captured_output *output)
{
    free(output->stdout_text);
    free(output->stderr_text);
    captured_output_init(output);
}

static int read_stream_text(FILE *stream, char **text_out)
{
    off_t stream_length;
    size_t length;
    size_t bytes_read;
    char *text;

    if (fflush(stream) != 0 || fseeko(stream, 0, SEEK_END) != 0) {
        return -1;
    }
    stream_length = ftello(stream);
    if (stream_length < 0) {
        return -1;
    }
    if ((uintmax_t)stream_length > (uintmax_t)SIZE_MAX - 1U) {
        return -1;
    }
    if (fseeko(stream, 0, SEEK_SET) != 0) {
        return -1;
    }

    length = (size_t)stream_length;
    text = (char *)malloc(length + 1);
    if (text == NULL) {
        return -1;
    }
    bytes_read = fread(text, 1, length, stream);
    if (bytes_read != length || ferror(stream) != 0) {
        free(text);
        return -1;
    }
    text[length] = '\0';
    *text_out = text;
    return 0;
}

static int capture_dispatch(struct tokens *tokens, struct captured_output *output)
{
    FILE *stdout_capture = NULL;
    FILE *stderr_capture = NULL;
    int saved_stdout = -1;
    int saved_stderr = -1;
    int stdout_redirected = 0;
    int stderr_redirected = 0;
    int dispatch_status = 1;
    int result = -1;
    int failure_errno = 0;

    captured_output_init(output);
    stdout_capture = tmpfile();
    stderr_capture = tmpfile();
    if (stdout_capture == NULL || stderr_capture == NULL) {
        failure_errno = errno;
        goto cleanup;
    }
    if (set_close_on_exec(fileno(stdout_capture)) != 0 ||
        set_close_on_exec(fileno(stderr_capture)) != 0) {
        failure_errno = errno;
        goto cleanup;
    }

    if (fflush(stdout) != 0 || fflush(stderr) != 0) {
        failure_errno = errno;
        goto cleanup;
    }
    saved_stdout = dup(STDOUT_FILENO);
    saved_stderr = dup(STDERR_FILENO);
    if (saved_stdout < 0 || saved_stderr < 0) {
        failure_errno = errno;
        goto cleanup;
    }
    if (set_close_on_exec(saved_stdout) != 0 ||
        set_close_on_exec(saved_stderr) != 0) {
        failure_errno = errno;
        goto restore;
    }
    if (dup2(fileno(stdout_capture), STDOUT_FILENO) < 0) {
        failure_errno = errno;
        goto restore;
    }
    stdout_redirected = 1;
    if (dup2(fileno(stderr_capture), STDERR_FILENO) < 0) {
        failure_errno = errno;
        goto restore;
    }
    stderr_redirected = 1;

    dispatch_status = dispatch(tokens);
    if (fflush(stdout) != 0 || fflush(stderr) != 0 ||
        read_stream_text(stdout_capture, &output->stdout_text) != 0 ||
        read_stream_text(stderr_capture, &output->stderr_text) != 0) {
        failure_errno = errno;
        goto restore;
    }
    result = dispatch_status;

restore:
    if (stdout_redirected && fflush(stdout) != 0 && failure_errno == 0) {
        failure_errno = errno;
        result = -1;
    }
    if (stderr_redirected && fflush(stderr) != 0 && failure_errno == 0) {
        failure_errno = errno;
        result = -1;
    }
    if (stdout_redirected && dup2(saved_stdout, STDOUT_FILENO) < 0) {
        if (failure_errno == 0) {
            failure_errno = errno;
        }
        result = -1;
    }
    if (stderr_redirected && dup2(saved_stderr, STDERR_FILENO) < 0) {
        if (failure_errno == 0) {
            failure_errno = errno;
        }
        result = -1;
    }

cleanup:
    if (saved_stdout >= 0) {
        if (close(saved_stdout) != 0 && failure_errno == 0) {
            failure_errno = errno;
            result = -1;
        }
    }
    if (saved_stderr >= 0) {
        if (close(saved_stderr) != 0 && failure_errno == 0) {
            failure_errno = errno;
            result = -1;
        }
    }
    if (stdout_capture != NULL) {
        if (fclose(stdout_capture) != 0 && failure_errno == 0) {
            failure_errno = errno;
            result = -1;
        }
    }
    if (stderr_capture != NULL) {
        if (fclose(stderr_capture) != 0 && failure_errno == 0) {
            failure_errno = errno;
            result = -1;
        }
    }
    if (result < 0) {
        captured_output_free(output);
    }
    if (failure_errno != 0) {
        errno = failure_errno;
    }
    return result;
}

static int capture_ls_parse_stderr(struct tokens *tokens,
                                   struct ls_request *request,
                                   char **stderr_text)
{
    FILE *stderr_capture = NULL;
    int saved_stderr = -1;
    int stderr_redirected = 0;
    int status = -1;
    int failure_errno = 0;

    *stderr_text = NULL;
    stderr_capture = tmpfile();
    if (stderr_capture == NULL) {
        return -1;
    }
    if (fflush(stderr) != 0) {
        failure_errno = errno;
        goto cleanup;
    }
    saved_stderr = dup(STDERR_FILENO);
    if (saved_stderr < 0) {
        failure_errno = errno;
        goto cleanup;
    }
    if (dup2(fileno(stderr_capture), STDERR_FILENO) < 0) {
        failure_errno = errno;
        goto cleanup;
    }
    stderr_redirected = 1;

    status = parse_ls_request(tokens, request);
    if (fflush(stderr) != 0 ||
        read_stream_text(stderr_capture, stderr_text) != 0) {
        failure_errno = errno;
        status = -1;
    }

cleanup:
    if (stderr_redirected && fflush(stderr) != 0 && failure_errno == 0) {
        failure_errno = errno;
        status = -1;
    }
    if (stderr_redirected && dup2(saved_stderr, STDERR_FILENO) < 0) {
        if (failure_errno == 0) {
            failure_errno = errno;
        }
        status = -1;
    }
    if (saved_stderr >= 0 && close(saved_stderr) != 0 && failure_errno == 0) {
        failure_errno = errno;
        status = -1;
    }
    if (fclose(stderr_capture) != 0 && failure_errno == 0) {
        failure_errno = errno;
        status = -1;
    }
    if (status < 0) {
        free(*stderr_text);
        *stderr_text = NULL;
    }
    if (failure_errno != 0) {
        errno = failure_errno;
    }
    return status;
}

static void test_ls_request_parser(void)
{
    struct {
        const char *command;
        int expected_status;
    } cases[] = {
        {"ls /tmp -laRtSh -- -dash", 0},
        {"ls -St .", 0},
        {"ls -", 0},
        {"ls -z", 2},
    };
    struct tokens tokens;
    struct ls_request request;
    char *stderr_text = NULL;
    size_t i;
    int parse_status;

    tokens_init(&tokens);
    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        tokens_free(&tokens);
        tokens_init(&tokens);
        ls_request_init(&request);
        parse_status = parse_line(cases[i].command, &tokens);
        CHECK(parse_status == 0, "failed to parse %s", cases[i].command);
        if (parse_status != 0) {
            ls_request_free(&request);
            continue;
        }

        if (cases[i].expected_status == 2) {
            parse_status = capture_ls_parse_stderr(
                &tokens, &request, &stderr_text);
            CHECK(parse_status == 2, "invalid ls parse returned %d",
                  parse_status);
            CHECK(stderr_text != NULL &&
                  strcmp(stderr_text,
                         "ls: invalid option -- 'z'\n"
                         "usage: ls [-laRtSh] [--] [path ...]\n") == 0,
                  "unexpected invalid ls stderr: %s",
                  stderr_text != NULL ? stderr_text : "<capture failed>");
            free(stderr_text);
            stderr_text = NULL;
        } else {
            parse_status = parse_ls_request(&tokens, &request);
            CHECK(parse_status == cases[i].expected_status,
                  "ls parse returned %d for %s",
                  parse_status,
                  cases[i].command);
        }

        if (strcmp(cases[i].command, "ls /tmp -laRtSh -- -dash") == 0 &&
            parse_status == 0) {
            CHECK(request.options.long_format, "expected -l");
            CHECK(request.options.show_all, "expected -a");
            CHECK(request.options.recursive, "expected -R");
            CHECK(request.options.human_readable, "expected -h");
            CHECK(request.options.sort_key == LS_SORT_SIZE,
                  "expected size sorting");
            CHECK(request.path_count == 2, "expected 2 ls paths, got %zu",
                  request.path_count);
            if (request.path_count == 2) {
                CHECK(strcmp(request.paths[0], "/tmp") == 0,
                      "expected first path /tmp");
                CHECK(strcmp(request.paths[1], "-dash") == 0,
                      "expected second path -dash");
            }
        }
        if (strcmp(cases[i].command, "ls -St .") == 0 &&
            parse_status == 0) {
            CHECK(request.options.sort_key == LS_SORT_MTIME,
                  "expected last sort option -t to win");
            CHECK(request.path_count == 1 &&
                  strcmp(request.paths[0], ".") == 0,
                  "expected . path after options");
        }
        if (strcmp(cases[i].command, "ls -") == 0 &&
            parse_status == 0) {
            CHECK(request.path_count == 1 &&
                  strcmp(request.paths[0], "-") == 0,
                  "expected lone dash operand");
        }
        ls_request_free(&request);
    }
    tokens_free(&tokens);
}

static void test_echo_baseline(void)
{
    struct tokens tokens;
    struct captured_output output;
    int parse_status;
    int status;

    tokens_init(&tokens);
    captured_output_init(&output);
    parse_status = parse_line("echo baseline", &tokens);
    CHECK(parse_status == 0, "failed to parse baseline command");
    CHECK(tokens.argc == 2, "expected 2 arguments, got %d", tokens.argc);
    if (parse_status == 0 && tokens.argc == 2) {
        status = capture_dispatch(&tokens, &output);
        CHECK(status == 0, "baseline dispatch returned %d", status);
        CHECK(output.stdout_text != NULL &&
              strcmp(output.stdout_text, "baseline\n") == 0,
              "expected stdout %s, got %s",
              "baseline\\n",
              output.stdout_text != NULL ? output.stdout_text : "<capture failed>");
        CHECK(output.stderr_text != NULL && output.stderr_text[0] == '\0',
              "expected empty stderr, got %s",
              output.stderr_text != NULL ? output.stderr_text : "<capture failed>");
    }
    captured_output_free(&output);
    tokens_free(&tokens);
}

static int run_command_capture(const char *command,
                               struct captured_output *output)
{
    struct tokens tokens;
    int parse_status;
    int status;

    tokens_init(&tokens);
    parse_status = parse_line(command, &tokens);
    if (parse_status != 0) {
        tokens_free(&tokens);
        return -1;
    }
    status = capture_dispatch(&tokens, output);
    tokens_free(&tokens);
    return status;
}

static int fixture_path(char *output,
                        size_t output_size,
                        const char *directory,
                        const char *name)
{
    int written = snprintf(output, output_size, "%s/%s", directory, name);

    return written >= 0 && (size_t)written < output_size ? 0 : -1;
}

static int create_fixture_file(const char *directory,
                               const char *name,
                               off_t size)
{
    char path[PATH_MAX];
    int descriptor;
    int status = 0;

    if (fixture_path(path, sizeof(path), directory, name) != 0) {
        return -1;
    }
    descriptor = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (descriptor < 0) {
        return -1;
    }
    if (ftruncate(descriptor, size) < 0) {
        status = -1;
    }
    if (close(descriptor) < 0) {
        status = -1;
    }
    return status;
}

static int cleanup_ls_fixture(const char *directory);

static int set_fixture_mtime(const char *directory,
                             const char *name,
                             time_t seconds,
                             long nanoseconds,
                             int nofollow)
{
    char path[PATH_MAX];
    struct timespec times[2];
    int flags = nofollow ? AT_SYMLINK_NOFOLLOW : 0;

    if (fixture_path(path, sizeof(path), directory, name) != 0) {
        return -1;
    }
    times[0].tv_sec = seconds;
    times[0].tv_nsec = nanoseconds;
    times[1] = times[0];
    return utimensat(AT_FDCWD, path, times, flags);
}

static int create_ls_fixture(char directory[PATH_MAX])
{
    const char *tmpdir = getenv("TMPDIR");
    char template[PATH_MAX];
    char sub_path[PATH_MAX];
    char link_path[PATH_MAX];
    char back_path[PATH_MAX];
    char *created;

    directory[0] = '\0';
    if (tmpdir == NULL || tmpdir[0] == '\0') {
        tmpdir = "/tmp";
    }
    if (snprintf(template, sizeof(template),
                 "%s/root-mini-shell-ls-XXXXXX", tmpdir) < 0 ||
        strlen(template) >= sizeof(template) - 1) {
        return -1;
    }
    created = mkdtemp(template);
    if (created == NULL) {
        return -1;
    }
    if (snprintf(directory, PATH_MAX, "%s", created) < 0 ||
        strlen(directory) >= PATH_MAX - 1) {
        cleanup_ls_fixture(created);
        directory[0] = '\0';
        return -1;
    }
    if (fixture_path(sub_path, sizeof(sub_path), directory, "sub") != 0 ||
        fixture_path(link_path, sizeof(link_path), directory,
                     "link-to-apple") != 0 ||
        fixture_path(back_path, sizeof(back_path), sub_path, "back") != 0 ||
        create_fixture_file(directory, ".hidden", 3) != 0 ||
        create_fixture_file(directory, "-dash", 4) != 0 ||
        create_fixture_file(directory, "apple", 8192) != 0 ||
        create_fixture_file(directory, "beta", 1024) != 0 ||
        create_fixture_file(directory, "equal-a", 64) != 0 ||
        create_fixture_file(directory, "equal-b", 64) != 0 ||
        create_fixture_file(directory, "nano-old", 64) != 0 ||
        create_fixture_file(directory, "nano-new", 64) != 0 ||
        mkdir(sub_path, 0755) != 0 ||
        create_fixture_file(sub_path, "nested.txt", 5) != 0 ||
        symlink("apple", link_path) != 0 ||
        symlink("..", back_path) != 0 ||
        set_fixture_mtime(directory, ".hidden", 150, 0, 0) != 0 ||
        set_fixture_mtime(directory, "-dash", 175, 0, 0) != 0 ||
        set_fixture_mtime(directory, "apple", 100, 0, 0) != 0 ||
        set_fixture_mtime(directory, "beta", 200, 0, 0) != 0 ||
        set_fixture_mtime(directory, "equal-a", 300, 0, 0) != 0 ||
        set_fixture_mtime(directory, "equal-b", 300, 0, 0) != 0 ||
        set_fixture_mtime(directory, "nano-old", 400, 100, 0) != 0 ||
        set_fixture_mtime(directory, "nano-new", 400, 200, 0) != 0 ||
        set_fixture_mtime(directory, "link-to-apple", 50, 0, 1) != 0 ||
        set_fixture_mtime(directory, "sub", 75, 0, 0) != 0) {
        cleanup_ls_fixture(directory);
        return -1;
    }
    return 0;
}

static int cleanup_ls_fixture(const char *directory)
{
    static const char *const files[] = {
        ".hidden", "-dash", "apple", "beta", "equal-a", "equal-b",
        "nano-old", "nano-new", "link-to-apple"
    };
    char path[PATH_MAX];
    size_t i;
    int status = 0;

    for (i = 0; i < sizeof(files) / sizeof(files[0]); ++i) {
        if (fixture_path(path, sizeof(path), directory, files[i]) == 0) {
            if (unlink(path) < 0 && errno != ENOENT) {
                status = -1;
            }
        }
    }
    if (fixture_path(path, sizeof(path), directory, "sub") == 0) {
        char nested_path[PATH_MAX];
        char back_path[PATH_MAX];

        if (fixture_path(nested_path, sizeof(nested_path), path,
                         "nested.txt") == 0 &&
            unlink(nested_path) < 0 && errno != ENOENT) {
            status = -1;
        }
        if (fixture_path(back_path, sizeof(back_path), path, "back") == 0 &&
            unlink(back_path) < 0 && errno != ENOENT) {
            status = -1;
        }
        if (rmdir(path) < 0 && errno != ENOENT) {
            status = -1;
        }
    }
    if (rmdir(directory) < 0 && errno != ENOENT) {
        status = -1;
    }
    return status;
}

static int create_completion_fixture(char directory[PATH_MAX])
{
    const char *tmpdir = getenv("TMPDIR");
    char template[PATH_MAX];
    char nested_path[PATH_MAX];
    char *created;

    directory[0] = '\0';
    if (tmpdir == NULL || tmpdir[0] == '\0') {
        tmpdir = "/tmp";
    }
    if (snprintf(template, sizeof(template),
                 "%s/root-mini-shell-completion-XXXXXX", tmpdir) < 0 ||
        strlen(template) >= sizeof(template) - 1) {
        return -1;
    }
    created = mkdtemp(template);
    if (created == NULL) {
        return -1;
    }
    if (snprintf(directory, PATH_MAX, "%s", created) < 0 ||
        strlen(directory) >= PATH_MAX - 1) {
        rmdir(created);
        directory[0] = '\0';
        return -1;
    }
    if (fixture_path(nested_path, sizeof(nested_path), directory,
                     "directory") != 0 ||
        mkdir(nested_path, 0755) != 0 ||
        create_fixture_file(directory, "alpha file", 1) != 0 ||
        create_fixture_file(directory, "dingo", 1) != 0 ||
        create_fixture_file(directory, "can't", 1) != 0 ||
        create_fixture_file(directory, "q\"slash\\end", 1) != 0 ||
        create_fixture_file(directory, ".hidden", 1) != 0 ||
        create_fixture_file(directory, "-dash", 1) != 0) {
        static const char *const files[] = {
            "alpha file", "dingo", "can't", "q\"slash\\end", ".hidden",
            "-dash"
        };
        size_t i;

        for (i = 0; i < sizeof(files) / sizeof(files[0]); ++i) {
            char path[PATH_MAX];

            if (fixture_path(path, sizeof(path), directory, files[i]) == 0) {
                unlink(path);
            }
        }
        rmdir(nested_path);
        rmdir(directory);
        directory[0] = '\0';
        return -1;
    }
    return 0;
}

static int cleanup_completion_fixture(const char *directory)
{
    static const char *const files[] = {
        "alpha file", "dingo", "can't", "q\"slash\\end", ".hidden", "-dash"
    };
    char path[PATH_MAX];
    size_t i;
    int status = 0;

    for (i = 0; i < sizeof(files) / sizeof(files[0]); ++i) {
        if (fixture_path(path, sizeof(path), directory, files[i]) == 0 &&
            unlink(path) < 0 && errno != ENOENT) {
            status = -1;
        }
    }
    if (fixture_path(path, sizeof(path), directory, "directory") == 0 &&
        rmdir(path) < 0 && errno != ENOENT) {
        status = -1;
    }
    if (rmdir(directory) < 0 && errno != ENOENT) {
        status = -1;
    }
    return status;
}

static void test_completion_core(void)
{
    char fixture[PATH_MAX];
    char absolute_line[PATH_MAX + 32];
    char line[PATH_MAX + 64];
    char original_line[PATH_MAX + 64];
    int original_directory_fd;
    struct completion_result result;
    size_t line_len;
    size_t cursor;
    int status;
    int restore_status;

    if (create_completion_fixture(fixture) != 0) {
        CHECK(0, "failed to create completion fixture");
        return;
    }
    original_directory_fd = open(".", O_RDONLY | O_DIRECTORY);
    if (original_directory_fd < 0 || chdir(fixture) != 0) {
        CHECK(0, "failed to enter completion fixture");
        if (original_directory_fd >= 0) {
            close(original_directory_fd);
        }
        cleanup_completion_fixture(fixture);
        return;
    }

    strcpy(line, "ls dire");
    line_len = strlen(line);
    cursor = line_len;
    completion_result_init(&result);
    status = completion_complete_line(
        line, sizeof(line), &line_len, &cursor, &result);
    CHECK(status == 0 && result.kind == COMPLETION_UNIQUE &&
          result.line_changed && strcmp(line, "ls directory/") == 0 &&
          cursor == strlen(line) && result.match_count == 1 &&
          result.matches != NULL && result.matches[0].name != NULL &&
          strcmp(result.matches[0].name, "directory") == 0 &&
          result.matches[0].is_directory,
          "directory completion failed: status=%d kind=%d line=%s",
          status, result.kind, line);
    completion_result_free(&result);

    strcpy(line, "ls d");
    line_len = strlen(line);
    cursor = line_len;
    completion_result_init(&result);
    status = completion_complete_line(
        line, sizeof(line), &line_len, &cursor, &result);
    CHECK(status == 0 && result.kind == COMPLETION_AMBIGUOUS &&
          result.line_changed && strcmp(line, "ls di") == 0 &&
          result.match_count == 2 &&
          strcmp(result.matches[0].name, "dingo") == 0 &&
          strcmp(result.matches[1].name, "directory") == 0,
          "ambiguous completion failed: status=%d kind=%d line=%s matches=%zu",
          status, result.kind, line, result.match_count);
    completion_result_free(&result);

    completion_result_init(&result);
    status = completion_complete_line(
        line, sizeof(line), &line_len, &cursor, &result);
    CHECK(status == 0 && result.kind == COMPLETION_AMBIGUOUS &&
          !result.line_changed && strcmp(line, "ls di") == 0,
          "repeated ambiguous completion changed line: status=%d kind=%d line=%s",
          status, result.kind, line);
    completion_result_free(&result);

    strcpy(line, "ls alpha");
    line_len = strlen(line);
    cursor = line_len;
    completion_result_init(&result);
    status = completion_complete_line(
        line, sizeof(line), &line_len, &cursor, &result);
    CHECK(status == 0 && result.kind == COMPLETION_UNIQUE &&
          strcmp(line, "ls alpha\\ file ") == 0,
          "unquoted space escaping failed: status=%d line=%s",
          status, line);
    completion_result_free(&result);

    strcpy(line, "ls 'ding");
    line_len = strlen(line);
    cursor = line_len;
    completion_result_init(&result);
    status = completion_complete_line(
        line, sizeof(line), &line_len, &cursor, &result);
    CHECK(status == 0 && result.kind == COMPLETION_UNIQUE &&
          strcmp(line, "ls 'dingo' ") == 0,
          "safe single-quote completion failed: status=%d line=%s",
          status, line);
    completion_result_free(&result);

    strcpy(line, "ls \"alpha");
    line_len = strlen(line);
    cursor = line_len;
    completion_result_init(&result);
    status = completion_complete_line(
        line, sizeof(line), &line_len, &cursor, &result);
    CHECK(status == 0 && result.kind == COMPLETION_UNIQUE &&
          strcmp(line, "ls \"alpha file\" ") == 0,
          "double quote completion failed: status=%d line=%s",
          status, line);
    completion_result_free(&result);

    strcpy(line, "ls \"q");
    line_len = strlen(line);
    cursor = line_len;
    completion_result_init(&result);
    status = completion_complete_line(
        line, sizeof(line), &line_len, &cursor, &result);
    CHECK(status == 0 && result.kind == COMPLETION_UNIQUE &&
          strcmp(line, "ls \"q\\\"slash\\\\end\" ") == 0,
          "double quote escaping completion failed: status=%d line=%s",
          status, line);
    completion_result_free(&result);

    strcpy(line, "ls -la dire");
    line_len = strlen(line);
    cursor = line_len;
    completion_result_init(&result);
    status = completion_complete_line(
        line, sizeof(line), &line_len, &cursor, &result);
    CHECK(status == 0 && result.kind == COMPLETION_UNIQUE &&
          strcmp(line, "ls -la directory/") == 0,
          "option-prefix completion failed: status=%d line=%s",
          status, line);
    completion_result_free(&result);

    strcpy(line, "ls -l");
    line_len = strlen(line);
    cursor = line_len;
    completion_result_init(&result);
    status = completion_complete_line(
        line, sizeof(line), &line_len, &cursor, &result);
    CHECK(status == 0 && result.kind == COMPLETION_NOT_APPLICABLE &&
          strcmp(line, "ls -l") == 0,
          "option token should be not applicable: status=%d kind=%d",
          status, result.kind);
    completion_result_free(&result);

    strcpy(line, "cat dire");
    line_len = strlen(line);
    cursor = line_len;
    completion_result_init(&result);
    status = completion_complete_line(
        line, sizeof(line), &line_len, &cursor, &result);
    CHECK(status == 0 && result.kind == COMPLETION_NOT_APPLICABLE &&
          strcmp(line, "cat dire") == 0,
          "non-ls command should be not applicable: status=%d kind=%d",
          status, result.kind);
    completion_result_free(&result);

    strcpy(line, "ls .h");
    line_len = strlen(line);
    cursor = line_len;
    completion_result_init(&result);
    status = completion_complete_line(
        line, sizeof(line), &line_len, &cursor, &result);
    CHECK(status == 0 && result.kind == COMPLETION_UNIQUE &&
          strcmp(line, "ls .hidden ") == 0,
          "hidden completion failed: status=%d line=%s",
          status, line);
    completion_result_free(&result);

    strcpy(line, "ls ");
    line_len = strlen(line);
    cursor = line_len;
    completion_result_init(&result);
    status = completion_complete_line(
        line, sizeof(line), &line_len, &cursor, &result);
    {
        size_t match_index;
        int hidden_found = 0;

        for (match_index = 0; match_index < result.match_count; ++match_index) {
            if (strcmp(result.matches[match_index].name, ".hidden") == 0) {
                hidden_found = 1;
            }
        }
        CHECK(status == 0 && result.kind == COMPLETION_AMBIGUOUS &&
              !hidden_found && strcmp(line, "ls ") == 0,
              "non-dot prefix exposed hidden or wrong candidates: "
              "status=%d kind=%d line=%s",
              status, result.kind, line);
    }
    completion_result_free(&result);

    strcpy(line, "ls dire tail");
    line_len = strlen(line);
    cursor = strlen("ls dire");
    completion_result_init(&result);
    status = completion_complete_line(
        line, sizeof(line), &line_len, &cursor, &result);
    CHECK(status == 0 && result.kind == COMPLETION_UNIQUE &&
          strcmp(line, "ls directory/ tail") == 0 &&
          cursor == strlen("ls directory/"),
          "middle-cursor completion failed: status=%d line=%s cursor=%zu",
          status, line, cursor);
    completion_result_free(&result);

    strcpy(line, "ls dire");
    strcpy(original_line, line);
    line_len = strlen(line);
    cursor = line_len;
    completion_result_init(&result);
    status = completion_complete_line(
        line, strlen(line) + 1, &line_len, &cursor, &result);
    CHECK(status == 0 && result.kind == COMPLETION_NO_MATCH &&
          !result.line_changed && strcmp(line, original_line) == 0 &&
          line_len == strlen(original_line) && cursor == line_len,
          "capacity failure did not preserve line: status=%d kind=%d line=%s",
          status, result.kind, line);
    completion_result_free(&result);

    strcpy(line, "ls zzz");
    strcpy(original_line, line);
    line_len = strlen(line);
    cursor = line_len;
    completion_result_init(&result);
    status = completion_complete_line(
        line, sizeof(line), &line_len, &cursor, &result);
    CHECK(status == 0 && result.kind == COMPLETION_NO_MATCH &&
          !result.line_changed && strcmp(line, original_line) == 0 &&
          line_len == strlen(original_line) && cursor == line_len,
          "nonexistent prefix changed line: status=%d kind=%d line=%s",
          status, result.kind, line);
    completion_result_free(&result);

    strcpy(line, "ls -- -d");
    line_len = strlen(line);
    cursor = line_len;
    completion_result_init(&result);
    status = completion_complete_line(
        line, sizeof(line), &line_len, &cursor, &result);
    CHECK(status == 0 && result.kind == COMPLETION_UNIQUE &&
          strcmp(line, "ls -- -dash ") == 0,
          "dash path after -- failed: status=%d line=%s",
          status, line);
    completion_result_free(&result);

    strcpy(line, "ls -");
    line_len = strlen(line);
    cursor = line_len;
    completion_result_init(&result);
    status = completion_complete_line(
        line, sizeof(line), &line_len, &cursor, &result);
    CHECK(status == 0 && result.kind == COMPLETION_UNIQUE &&
          strcmp(line, "ls -dash ") == 0,
          "lone dash path completion failed: status=%d line=%s",
          status, line);
    completion_result_free(&result);

    strcpy(line, "ls -d");
    line_len = strlen(line);
    cursor = line_len;
    completion_result_init(&result);
    status = completion_complete_line(
        line, sizeof(line), &line_len, &cursor, &result);
    CHECK(status == 0 && result.kind == COMPLETION_NOT_APPLICABLE &&
          strcmp(line, "ls -d") == 0,
          "dash option should not complete: status=%d kind=%d",
          status, result.kind);
    completion_result_free(&result);

    strcpy(line, "ls 'can");
    line_len = strlen(line);
    cursor = line_len;
    completion_result_init(&result);
    status = completion_complete_line(
        line, sizeof(line), &line_len, &cursor, &result);
    CHECK(status == 0 && result.kind == COMPLETION_NO_MATCH &&
          !result.line_changed && strcmp(line, "ls 'can") == 0,
          "unsafe single-quoted completion changed line: status=%d kind=%d line=%s",
          status, result.kind, line);
    completion_result_free(&result);

    CHECK(snprintf(absolute_line, sizeof(absolute_line), "ls %s/al",
                   fixture) > 0, "failed to format absolute completion line");
    line_len = strlen(absolute_line);
    cursor = line_len;
    completion_result_init(&result);
    status = completion_complete_line(
        absolute_line, sizeof(absolute_line), &line_len, &cursor, &result);
    CHECK(status == 0 && result.kind == COMPLETION_UNIQUE &&
          snprintf(original_line, sizeof(original_line), "ls %s/alpha\\ file ",
                   fixture) > 0 &&
          strcmp(absolute_line, original_line) == 0,
          "absolute completion unexpectedly changed prefix: status=%d line=%s",
          status, absolute_line);
    completion_result_free(&result);

    restore_status = fchdir(original_directory_fd);
    CHECK(restore_status == 0, "failed to restore current directory");
    if (restore_status == 0) {
        CHECK(cleanup_completion_fixture(fixture) == 0,
              "failed to clean up completion fixture");
    }
    CHECK(close(original_directory_fd) == 0,
          "failed to close saved completion directory");
}

static int line_index(const char *text, const char *line)
{
    size_t line_length = strlen(line);
    int index = 0;

    while (*text != '\0') {
        const char *line_end = strchr(text, '\n');
        size_t current_length = line_end == NULL
                                    ? strlen(text)
                                    : (size_t)(line_end - text);

        if (current_length == line_length &&
            memcmp(text, line, line_length) == 0) {
            return index;
        }
        if (line_end == NULL) {
            break;
        }
        text = line_end + 1;
        ++index;
    }
    return -1;
}

static void test_ls_ancestor_chain(void)
{
    struct ls_ancestor root = {7, 11, NULL};
    struct ls_ancestor child = {13, 17, &root};

    CHECK(ls_ancestor_contains(&root, 7, 11),
          "ancestor helper missed root device/inode");
    CHECK(!ls_ancestor_contains(&root, 13, 17),
          "ancestor helper matched unrelated child");
    CHECK(ls_ancestor_contains(&child, 7, 11),
          "ancestor helper missed parent device/inode");
    CHECK(ls_ancestor_contains(&child, 13, 17),
          "ancestor helper missed child device/inode");
    CHECK(!ls_ancestor_contains(&child, 13, 19),
          "ancestor helper ignored inode mismatch");
    CHECK(!ls_ancestor_contains(&child, 19, 17),
          "ancestor helper ignored device mismatch");
}

static void test_human_size_boundaries(void)
{
    char output[64];

    if (sizeof(off_t) >= sizeof(uint64_t)) {
        format_human_size((off_t)(UINTMAX_C(1) << 50), output);
        CHECK(strcmp(output, "1.0P") == 0,
              "expected pebibyte human size, got %s", output);
        format_human_size((off_t)(UINTMAX_C(1) << 60), output);
        CHECK(strcmp(output, "1.0E") == 0,
              "expected exbibyte human size, got %s", output);
    }
}

static int contains_timestamp_pattern(const char *text)
{
    const char *cursor;
    size_t remaining;

    for (cursor = text, remaining = strlen(text);
         remaining >= 16;
         ++cursor, --remaining) {
        if (isdigit((unsigned char)cursor[0]) &&
            isdigit((unsigned char)cursor[1]) &&
            isdigit((unsigned char)cursor[2]) &&
            isdigit((unsigned char)cursor[3]) &&
            cursor[4] == '-' &&
            isdigit((unsigned char)cursor[5]) &&
            isdigit((unsigned char)cursor[6]) &&
            cursor[7] == '-' &&
            isdigit((unsigned char)cursor[8]) &&
            isdigit((unsigned char)cursor[9]) &&
            cursor[10] == ' ' &&
            isdigit((unsigned char)cursor[11]) &&
            isdigit((unsigned char)cursor[12]) &&
            cursor[13] == ':' &&
            isdigit((unsigned char)cursor[14]) &&
            isdigit((unsigned char)cursor[15])) {
            return 1;
        }
    }
    return 0;
}

static void test_ls_listing(void)
{
    char fixture[PATH_MAX];
    char mode[11];
    struct captured_output output;
    int original_directory_fd;
    int restore_status;
    int status;

    original_directory_fd = open(".", O_RDONLY | O_DIRECTORY);
    CHECK(original_directory_fd >= 0, "failed to save current directory");
    if (original_directory_fd < 0) {
        return;
    }
    if (create_ls_fixture(fixture) != 0) {
        CHECK(0, "failed to create ls fixture");
        CHECK(close(original_directory_fd) == 0,
              "failed to close saved current directory");
        return;
    }
    if (chdir(fixture) != 0) {
        int restore_status = fchdir(original_directory_fd);

        CHECK(0, "failed to enter ls fixture");
        CHECK(restore_status == 0,
              "failed to restore current directory after chdir failure");
        if (restore_status == 0) {
            CHECK(cleanup_ls_fixture(fixture) == 0,
                  "failed to clean up ls fixture");
        }
        CHECK(close(original_directory_fd) == 0,
              "failed to close saved current directory");
        return;
    }

    status = run_command_capture("ls .", &output);
    CHECK(status == 0, "plain ls returned %d", status);
    CHECK(output.stdout_text != NULL &&
          strcmp(output.stdout_text,
                 "-dash\napple\nbeta\nequal-a\nequal-b\n"
                 "link-to-apple\nnano-new\nnano-old\nsub\n") == 0,
          "unexpected plain ls output: %s",
          output.stdout_text != NULL ? output.stdout_text : "<capture failed>");
    CHECK(output.stderr_text != NULL && output.stderr_text[0] == '\0',
          "plain ls wrote stderr: %s",
          output.stderr_text != NULL ? output.stderr_text : "<capture failed>");
    captured_output_free(&output);

    status = run_command_capture("ls -h .", &output);
    CHECK(status == 0, "ls -h returned %d", status);
    CHECK(output.stdout_text != NULL &&
          strcmp(output.stdout_text,
                 "-dash\napple\nbeta\nequal-a\nequal-b\n"
                 "link-to-apple\nnano-new\nnano-old\nsub\n") == 0,
          "unexpected ls -h output: %s",
          output.stdout_text != NULL ? output.stdout_text : "<capture failed>");
    captured_output_free(&output);

    status = run_command_capture("ls -tS .", &output);
    CHECK(status == 0 && output.stdout_text != NULL &&
          strncmp(output.stdout_text, "apple\n", 6) == 0,
          "ls -tS did not sort by size: %s",
          output.stdout_text != NULL ? output.stdout_text : "<capture failed>");
    captured_output_free(&output);

    status = run_command_capture("ls -S .", &output);
    CHECK(status == 0 && output.stdout_text != NULL &&
          line_index(output.stdout_text, "equal-a") >= 0 &&
          line_index(output.stdout_text, "equal-b") >= 0 &&
          line_index(output.stdout_text, "equal-a") <
              line_index(output.stdout_text, "equal-b"),
          "equal-size entries did not use name tiebreaker: %s",
          output.stdout_text != NULL ? output.stdout_text : "<capture failed>");
    captured_output_free(&output);

    status = run_command_capture("ls -t .", &output);
    CHECK(status == 0 && output.stdout_text != NULL &&
          line_index(output.stdout_text, "equal-a") >= 0 &&
          line_index(output.stdout_text, "equal-b") >= 0 &&
          line_index(output.stdout_text, "equal-a") <
              line_index(output.stdout_text, "equal-b"),
          "equal-mtime entries did not use name tiebreaker: %s",
          output.stdout_text != NULL ? output.stdout_text : "<capture failed>");
#if LS_HAS_MTIME_NSEC
    CHECK(output.stdout_text != NULL &&
          line_index(output.stdout_text, "nano-new") >= 0 &&
          line_index(output.stdout_text, "nano-old") >= 0 &&
          line_index(output.stdout_text, "nano-new") <
              line_index(output.stdout_text, "nano-old"),
          "nanosecond mtime ordering was not descending: %s",
          output.stdout_text != NULL ? output.stdout_text : "<capture failed>");
#endif
    captured_output_free(&output);

    status = run_command_capture("ls -St .", &output);
    CHECK(status == 0 && output.stdout_text != NULL &&
          strncmp(output.stdout_text, "nano-new\n", 9) == 0,
          "ls -St did not sort by mtime: %s",
          output.stdout_text != NULL ? output.stdout_text : "<capture failed>");
    captured_output_free(&output);

    status = run_command_capture("ls -- -dash", &output);
    CHECK(status == 0 && output.stdout_text != NULL &&
          strcmp(output.stdout_text, "-dash\n") == 0,
          "unexpected -- operand output: %s",
          output.stdout_text != NULL ? output.stdout_text : "<capture failed>");
    captured_output_free(&output);

    status = run_command_capture("ls -z", &output);
    CHECK(status == 2, "invalid ls dispatch returned %d", status);
    CHECK(output.stdout_text != NULL && output.stdout_text[0] == '\0',
          "invalid ls wrote stdout: %s",
          output.stdout_text != NULL ? output.stdout_text : "<capture failed>");
    CHECK(output.stderr_text != NULL &&
          strcmp(output.stderr_text,
                 "ls: invalid option -- 'z'\n"
                 "usage: ls [-laRtSh] [--] [path ...]\n") == 0,
          "unexpected invalid ls stderr: %s",
          output.stderr_text != NULL ? output.stderr_text : "<capture failed>");
    captured_output_free(&output);

    status = run_command_capture("ls -lah .", &output);
    CHECK(status == 0, "ls -lah returned %d", status);
    CHECK(output.stdout_text != NULL &&
          strstr(output.stdout_text, " .\n") != NULL &&
          strstr(output.stdout_text, " ..\n") != NULL &&
          strstr(output.stdout_text, ".hidden\n") != NULL &&
          strstr(output.stdout_text, "8.0K") != NULL &&
          strstr(output.stdout_text, "link-to-apple -> apple\n") != NULL,
          "ls -lah omitted required entries: %s",
          output.stdout_text != NULL ? output.stdout_text : "<capture failed>");
    captured_output_free(&output);

    status = run_command_capture("ls -l apple", &output);
    CHECK(status == 0 && output.stdout_text != NULL &&
          strstr(output.stdout_text, " 8192 ") != NULL &&
          contains_timestamp_pattern(output.stdout_text),
          "long apple row lacks numeric metadata/timestamp: %s",
          output.stdout_text != NULL ? output.stdout_text : "<capture failed>");
    captured_output_free(&output);

    format_mode(S_IFREG | S_IRUSR | S_IWUSR | S_IXUSR | S_ISUID, mode);
    CHECK(strcmp(mode, "-rws------") == 0,
          "unexpected setuid mode: %s", mode);
    format_mode(S_IFREG | S_IRGRP | S_IXGRP | S_ISGID, mode);
    CHECK(strcmp(mode, "----r-s---") == 0,
          "unexpected setgid mode: %s", mode);
    format_mode(S_IFREG | S_IROTH | S_IWOTH | S_IXOTH | S_ISVTX, mode);
    CHECK(strcmp(mode, "-------rwt") == 0,
          "unexpected sticky mode: %s", mode);

    status = run_command_capture("ls missing .", &output);
    CHECK(status == 1, "missing operand returned %d", status);
    CHECK(output.stdout_text != NULL &&
          strstr(output.stdout_text, "missing:\n\n.:\n") != NULL,
          "missing operand did not preserve valid listing/header: %s",
          output.stdout_text != NULL ? output.stdout_text : "<capture failed>");
    CHECK(output.stderr_text != NULL &&
          strstr(output.stderr_text, "ls: missing: ") != NULL,
          "missing operand lacked diagnostic: %s",
          output.stderr_text != NULL ? output.stderr_text : "<capture failed>");
    captured_output_free(&output);

    status = run_command_capture("ls -R .", &output);
    CHECK(status == 0, "recursive ls returned %d", status);
    CHECK(output.stdout_text != NULL &&
          strstr(output.stdout_text, ".:\n") != NULL &&
          strstr(output.stdout_text, "./sub:\n") != NULL &&
          strstr(output.stdout_text, "nested.txt\n") != NULL &&
          strstr(output.stdout_text, "./sub/back:\n") == NULL,
          "recursive ls output was incorrect: %s",
          output.stdout_text != NULL ? output.stdout_text : "<capture failed>");
    CHECK(output.stderr_text != NULL && output.stderr_text[0] == '\0',
          "recursive ls wrote stderr: %s",
          output.stderr_text != NULL ? output.stderr_text : "<capture failed>");
    captured_output_free(&output);

    status = run_command_capture("ls -aR .", &output);
    CHECK(status == 0, "recursive all ls returned %d", status);
    CHECK(output.stdout_text != NULL &&
          strstr(output.stdout_text, ".:\n") != NULL &&
          strstr(output.stdout_text, "./sub:\n") != NULL &&
          strstr(output.stdout_text, ".\n") != NULL &&
          strstr(output.stdout_text, "..\n") != NULL &&
          strstr(output.stdout_text, "./.:\n") == NULL &&
          strstr(output.stdout_text, "./..:\n") == NULL &&
          strstr(output.stdout_text, "./sub/.:\n") == NULL &&
          strstr(output.stdout_text, "./sub/..:\n") == NULL,
          "recursive all ls recursed dot entries: %s",
          output.stdout_text != NULL ? output.stdout_text : "<capture failed>");
    captured_output_free(&output);

    status = run_command_capture("ls . sub", &output);
    CHECK(status == 0, "multiple valid ls returned %d", status);
    CHECK(output.stdout_text != NULL &&
          strstr(output.stdout_text, ".:\n") != NULL &&
          strstr(output.stdout_text, "\n\nsub:\n") != NULL,
          "multiple valid operands lacked headers/separator: %s",
          output.stdout_text != NULL ? output.stdout_text : "<capture failed>");
    captured_output_free(&output);

    restore_status = fchdir(original_directory_fd);
    CHECK(restore_status == 0, "failed to restore current directory");
    if (restore_status == 0) {
        CHECK(cleanup_ls_fixture(fixture) == 0,
              "failed to clean up ls fixture");
    }
    CHECK(close(original_directory_fd) == 0,
          "failed to close saved current directory");
}

int main(void)
{
    test_echo_baseline();
    test_ls_request_parser();
    test_ls_ancestor_chain();
    test_human_size_boundaries();
    test_ls_listing();
    test_completion_core();
    if (g_failures != 0) {
        fprintf(stderr, "root_mini_shell tests: FAIL (%d failures)\n", g_failures);
        return 1;
    }

    puts("root_mini_shell tests: PASS");
    return 0;
}
