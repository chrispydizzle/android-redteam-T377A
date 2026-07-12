#define _GNU_SOURCE

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <inttypes.h>
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
#include <termios.h>
#include <time.h>
#include <unistd.h>

#if defined(__ANDROID__)
#if defined(__ANDROID_API__) && __ANDROID_API__ >= 21
#define LS_HAS_MTIME_NSEC 1
#endif
#elif defined(__linux__)
#define LS_HAS_MTIME_NSEC 1
#endif

#ifndef LS_HAS_MTIME_NSEC
#define LS_HAS_MTIME_NSEC 0
#endif

extern char **environ;

static volatile sig_atomic_t g_interrupted = 0;
static struct termios g_saved_termios;
static int g_termios_saved = 0;

struct tokens {
    char **argv;
    size_t argc;
    size_t cap;
};

enum ls_sort_key {
    LS_SORT_NAME,
    LS_SORT_MTIME,
    LS_SORT_SIZE
};

struct ls_options {
    bool long_format;
    bool show_all;
    bool recursive;
    bool human_readable;
    enum ls_sort_key sort_key;
};

struct ls_request {
    struct ls_options options;
    const char **paths;
    size_t path_count;
};

struct ls_entry {
    char *name;
    char *full_path;
    struct stat st;
};

struct ls_entry_list {
    struct ls_entry *items;
    size_t count;
    size_t capacity;
};

struct ls_ancestor {
    dev_t st_dev;
    ino_t st_ino;
    const struct ls_ancestor *parent;
};

struct ls_output {
    int stdout_failed;
    int stdout_failure_reported;
    int output_started;
};

enum quote_mode {
    QUOTE_NONE = 0,
    QUOTE_SINGLE,
    QUOTE_DOUBLE,
};

enum completion_result_kind {
    COMPLETION_NOT_APPLICABLE = 0,
    COMPLETION_NO_MATCH,
    COMPLETION_UNIQUE,
    COMPLETION_AMBIGUOUS,
};

struct completion_match {
    char *name;
    bool is_directory;
};

struct completion_result {
    enum completion_result_kind kind;
    struct completion_match *matches;
    size_t match_count;
    bool line_changed;
};

static void tokens_init(struct tokens *tokens);
static void tokens_free(struct tokens *tokens);
static int tokens_append(struct tokens *tokens, const char *value);

void completion_result_init(struct completion_result *result)
{
    if (result == NULL) {
        return;
    }
    result->kind = COMPLETION_NOT_APPLICABLE;
    result->matches = NULL;
    result->match_count = 0;
    result->line_changed = false;
}

void completion_result_free(struct completion_result *result)
{
    size_t i;

    if (result == NULL) {
        return;
    }
    for (i = 0; i < result->match_count; ++i) {
        free(result->matches[i].name);
    }
    free(result->matches);
    completion_result_init(result);
}

struct completion_scan {
    struct tokens tokens;
    bool active;
    size_t raw_start;
    size_t raw_basename_start;
    enum quote_mode quote;
};

static void completion_scan_init(struct completion_scan *scan)
{
    tokens_init(&scan->tokens);
    scan->active = false;
    scan->raw_start = 0;
    scan->raw_basename_start = 0;
    scan->quote = QUOTE_NONE;
}

static void completion_scan_free(struct completion_scan *scan)
{
    tokens_free(&scan->tokens);
    scan->active = false;
}

static int completion_parse_prefix(const char *line,
                                   size_t prefix_length,
                                   struct completion_scan *scan)
{
    char *token_buf;
    size_t i;
    size_t token_len = 0;
    size_t raw_start = 0;
    size_t raw_basename_start = 0;
    bool in_token = false;
    bool decoded_since_basename = false;
    bool escaped = false;
    enum quote_mode quote = QUOTE_NONE;

    token_buf = (char *)malloc(prefix_length + 1);
    if (token_buf == NULL) {
        return -1;
    }

    for (i = 0; i < prefix_length; ++i) {
        unsigned char c = (unsigned char)line[i];

        if (!in_token && quote == QUOTE_NONE && isspace(c)) {
            continue;
        }
        if (!in_token) {
            raw_start = i;
            raw_basename_start = i;
            token_len = 0;
            decoded_since_basename = false;
            in_token = true;
        }

        if (escaped) {
            token_buf[token_len++] = (char)c;
            escaped = false;
            if (c == '/') {
                raw_basename_start = i + 1;
                decoded_since_basename = false;
            } else {
                decoded_since_basename = true;
            }
            continue;
        }

        if (quote == QUOTE_NONE && isspace(c)) {
            token_buf[token_len] = '\0';
            if (tokens_append(&scan->tokens, token_buf) != 0) {
                free(token_buf);
                return -1;
            }
            in_token = false;
            continue;
        }

        if (quote != QUOTE_SINGLE && c == '\\') {
            escaped = true;
            continue;
        }

        if (c == '\'' && quote != QUOTE_DOUBLE) {
            if (!decoded_since_basename) {
                raw_basename_start = i + 1;
            }
            quote = quote == QUOTE_SINGLE ? QUOTE_NONE : QUOTE_SINGLE;
            continue;
        }

        if (c == '"' && quote != QUOTE_SINGLE) {
            if (!decoded_since_basename) {
                raw_basename_start = i + 1;
            }
            quote = quote == QUOTE_DOUBLE ? QUOTE_NONE : QUOTE_DOUBLE;
            continue;
        }

        token_buf[token_len++] = (char)c;
        if (c == '/') {
            raw_basename_start = i + 1;
            decoded_since_basename = false;
        } else {
            decoded_since_basename = true;
        }
    }

    if (in_token) {
        token_buf[token_len] = '\0';
        if (tokens_append(&scan->tokens, token_buf) != 0) {
            free(token_buf);
            return -1;
        }
        scan->active = true;
        scan->raw_start = raw_start;
        scan->raw_basename_start = raw_basename_start;
        scan->quote = quote;
    }
    free(token_buf);
    return 0;
}

static int completion_append_match(struct completion_result *result,
                                   const char *name,
                                   bool is_directory)
{
    struct completion_match *new_matches;
    char *name_copy;

    name_copy = strdup(name);
    if (name_copy == NULL) {
        return -1;
    }
    if (result->match_count == (size_t)-1 ||
        result->match_count + 1 >
            (size_t)-1 / sizeof(result->matches[0])) {
        free(name_copy);
        return -1;
    }
    new_matches = (struct completion_match *)realloc(
        result->matches,
        (result->match_count + 1) * sizeof(result->matches[0]));
    if (new_matches == NULL) {
        free(name_copy);
        return -1;
    }
    result->matches = new_matches;
    result->matches[result->match_count].name = name_copy;
    result->matches[result->match_count].is_directory = is_directory;
    ++result->match_count;
    return 0;
}

static int compare_completion_matches(const void *left_pointer,
                                      const void *right_pointer)
{
    const struct completion_match *left =
        (const struct completion_match *)left_pointer;
    const struct completion_match *right =
        (const struct completion_match *)right_pointer;

    return strcmp(left->name, right->name);
}

static char *completion_join_path(const char *directory, const char *name)
{
    size_t directory_length = strlen(directory);
    size_t name_length = strlen(name);
    bool needs_separator = directory_length > 0 &&
                           directory[directory_length - 1] != '/';
    size_t total_length;
    char *path;

    if (directory_length > (size_t)-1 - name_length - (needs_separator ? 1 : 0) -
                                1) {
        return NULL;
    }
    total_length = directory_length + name_length +
                   (needs_separator ? 1 : 0) + 1;
    path = (char *)malloc(total_length);
    if (path == NULL) {
        return NULL;
    }
    if (needs_separator) {
        snprintf(path, total_length, "%s/%s", directory, name);
    } else {
        snprintf(path, total_length, "%s%s", directory, name);
    }
    return path;
}

static int completion_collect_matches(const char *decoded_path,
                                      struct completion_result *result,
                                      char **basename_out)
{
    const char *slash;
    size_t parent_length;
    const char *basename;
    char *parent = NULL;
    DIR *directory = NULL;
    struct dirent *entry;
    bool show_hidden;
    int status = 0;

    slash = strrchr(decoded_path, '/');
    if (slash == NULL) {
        parent = strdup(".");
        basename = decoded_path;
    } else {
        parent_length = (size_t)(slash - decoded_path);
        if (parent_length == 0) {
            parent = strdup("/");
        } else {
            parent = (char *)malloc(parent_length + 1);
            if (parent != NULL) {
                memcpy(parent, decoded_path, parent_length);
                parent[parent_length] = '\0';
            }
        }
        basename = slash + 1;
    }
    if (parent == NULL) {
        return -1;
    }
    *basename_out = strdup(basename);
    if (*basename_out == NULL) {
        free(parent);
        return -1;
    }
    show_hidden = basename[0] == '.';
    directory = opendir(parent);
    if (directory == NULL) {
        free(parent);
        return 0;
    }
    while ((entry = readdir(directory)) != NULL) {
        char *entry_path;
        struct stat entry_stat;

        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0 ||
            (!show_hidden && entry->d_name[0] == '.') ||
            strncmp(entry->d_name, basename, strlen(basename)) != 0) {
            continue;
        }
        entry_path = completion_join_path(parent, entry->d_name);
        if (entry_path == NULL) {
            status = -1;
            break;
        }
        if (stat(entry_path, &entry_stat) == 0 &&
            completion_append_match(result, entry->d_name,
                                    S_ISDIR(entry_stat.st_mode)) != 0) {
            status = -1;
            free(entry_path);
            break;
        }
        free(entry_path);
    }
    if (closedir(directory) < 0 && status == 0) {
        status = -1;
    }
    free(parent);
    if (status != 0) {
        free(*basename_out);
        *basename_out = NULL;
    }
    return status;
}

static char *completion_escape_name(const char *name, enum quote_mode quote)
{
    size_t i;
    size_t output_length = 0;
    char *output;
    size_t cursor = 0;

    for (i = 0; name[i] != '\0'; ++i) {
        bool needs_escape = quote == QUOTE_NONE &&
                            (isspace((unsigned char)name[i]) ||
                             name[i] == '\\' || name[i] == '\'' ||
                             name[i] == '"');

        if (quote == QUOTE_SINGLE && name[i] == '\'') {
            return NULL;
        }
        if (needs_escape ||
            (quote == QUOTE_DOUBLE &&
             (name[i] == '\\' || name[i] == '"'))) {
            if (output_length == (size_t)-1) {
                return NULL;
            }
            ++output_length;
        }
        if (output_length == (size_t)-1) {
            return NULL;
        }
        ++output_length;
    }
    output = (char *)malloc(output_length + 1);
    if (output == NULL) {
        return NULL;
    }
    for (i = 0; name[i] != '\0'; ++i) {
        bool needs_escape = quote == QUOTE_NONE &&
                            (isspace((unsigned char)name[i]) ||
                             name[i] == '\\' || name[i] == '\'' ||
                             name[i] == '"');

        if (needs_escape ||
            (quote == QUOTE_DOUBLE &&
             (name[i] == '\\' || name[i] == '"'))) {
            output[cursor++] = '\\';
        }
        output[cursor++] = name[i];
    }
    output[cursor] = '\0';
    return output;
}

static size_t completion_common_prefix(const struct completion_result *result)
{
    size_t common_length;
    size_t i;

    if (result->match_count == 0) {
        return 0;
    }
    common_length = strlen(result->matches[0].name);
    for (i = 1; i < result->match_count; ++i) {
        size_t current = 0;

        while (current < common_length &&
               result->matches[0].name[current] ==
                   result->matches[i].name[current]) {
            ++current;
        }
        common_length = current;
    }
    return common_length;
}

static int completion_apply_insertion(char *line,
                                      size_t capacity,
                                      size_t *line_len,
                                      size_t *cursor,
                                      size_t replace_start,
                                      const char *replacement,
                                      bool append_delimiter,
                                      enum quote_mode quote,
                                      bool is_directory)
{
    size_t replacement_length = strlen(replacement);
    size_t delimiter_length = 0;
    size_t new_length;
    char *insertion;
    size_t insertion_length;

    if (replace_start > *cursor || *cursor > *line_len) {
        return 0;
    }
    if (append_delimiter) {
        if (is_directory) {
            delimiter_length = 1;
        } else if (quote == QUOTE_NONE) {
            delimiter_length = 1;
        } else {
            delimiter_length = 2;
        }
    }
    if (replacement_length > (size_t)-1 - delimiter_length ||
        *line_len - *cursor > (size_t)-1 - replacement_length -
                                  delimiter_length ||
        *line_len - (*cursor - replace_start) >
            (size_t)-1 - replacement_length - delimiter_length) {
        return 0;
    }
    new_length = *line_len - (*cursor - replace_start) +
                 replacement_length + delimiter_length;
    if (new_length >= capacity) {
        return 0;
    }
    insertion_length = replacement_length + delimiter_length;
    insertion = (char *)malloc(insertion_length + 1);
    if (insertion == NULL) {
        return -1;
    }
    memcpy(insertion, replacement, replacement_length);
    if (delimiter_length != 0) {
        size_t delimiter_cursor = replacement_length;

        if (is_directory) {
            insertion[delimiter_cursor] = '/';
        } else if (quote == QUOTE_NONE) {
            insertion[delimiter_cursor] = ' ';
        } else {
            insertion[delimiter_cursor] = quote == QUOTE_SINGLE ? '\'' : '"';
            insertion[delimiter_cursor + 1] = ' ';
        }
    }
    insertion[insertion_length] = '\0';
    memmove(line + replace_start + insertion_length,
            line + *cursor,
            *line_len - *cursor + 1);
    memcpy(line + replace_start, insertion, insertion_length);
    *line_len = new_length;
    *cursor = replace_start + insertion_length;
    free(insertion);
    return 1;
}

int completion_complete_line(char *line,
                             size_t capacity,
                             size_t *line_len,
                             size_t *cursor,
                             struct completion_result *result)
{
    struct completion_scan scan;
    const char *current_value;
    const char *basename;
    char *decoded_basename = NULL;
    char *escaped_name = NULL;
    char *decoded_path = NULL;
    size_t current_index;
    size_t i;
    size_t common_length;
    size_t replace_start;
    bool end_options = false;
    bool append_delimiter;
    bool is_directory = false;
    int insertion_status;

    if (line == NULL || line_len == NULL || cursor == NULL || result == NULL ||
        capacity == 0 || *line_len >= capacity || *cursor > *line_len ||
        line[*line_len] != '\0') {
        return -1;
    }
    completion_result_free(result);
    completion_scan_init(&scan);
    if (completion_parse_prefix(line, *cursor, &scan) != 0) {
        completion_scan_free(&scan);
        return -1;
    }
    if (scan.tokens.argc == 0 ||
        strcmp(scan.tokens.argv[0], "ls") != 0) {
        completion_scan_free(&scan);
        return 0;
    }
    current_index = scan.active ? scan.tokens.argc - 1 : scan.tokens.argc;
    if (current_index == 0) {
        completion_scan_free(&scan);
        return 0;
    }
    for (i = 1; i < current_index; ++i) {
        current_value = scan.tokens.argv[i];
        if (end_options) {
            continue;
        }
        if (strcmp(current_value, "--") == 0) {
            end_options = true;
        }
    }
    if (scan.active) {
        current_value = scan.tokens.argv[current_index];
        if (!end_options && current_value[0] == '-' &&
            current_value[1] != '\0') {
            completion_scan_free(&scan);
            return 0;
        }
        decoded_path = strdup(current_value);
        replace_start = scan.raw_basename_start;
        current_value = scan.tokens.argv[current_index];
    } else {
        current_value = "";
        decoded_path = strdup("");
        replace_start = *cursor;
        scan.quote = QUOTE_NONE;
    }
    if (decoded_path == NULL) {
        completion_scan_free(&scan);
        return -1;
    }
    if (completion_collect_matches(decoded_path, result, &decoded_basename) != 0) {
        free(decoded_path);
        completion_scan_free(&scan);
        completion_result_free(result);
        return -1;
    }
    free(decoded_path);
    completion_scan_free(&scan);
    if (result->match_count == 0) {
        result->kind = COMPLETION_NO_MATCH;
        free(decoded_basename);
        return 0;
    }
    qsort(result->matches, result->match_count, sizeof(result->matches[0]),
          compare_completion_matches);
    result->kind = result->match_count == 1
                       ? COMPLETION_UNIQUE
                       : COMPLETION_AMBIGUOUS;
    basename = decoded_basename;
    if (result->kind == COMPLETION_UNIQUE) {
        is_directory = result->matches[0].is_directory;
        escaped_name = completion_escape_name(result->matches[0].name,
                                              scan.quote);
        if (escaped_name == NULL) {
            completion_result_free(result);
            result->kind = COMPLETION_NO_MATCH;
            free(decoded_basename);
            return 0;
        }
    } else {
        common_length = completion_common_prefix(result);
        if (common_length <= strlen(basename)) {
            free(decoded_basename);
            return 0;
        }
        {
            char *common_name = (char *)malloc(common_length + 1);

            if (common_name == NULL) {
                free(decoded_basename);
                completion_result_free(result);
                return -1;
            }
            memcpy(common_name, result->matches[0].name, common_length);
            common_name[common_length] = '\0';
            escaped_name = completion_escape_name(common_name, scan.quote);
            free(common_name);
        }
        if (escaped_name == NULL) {
            completion_result_free(result);
            result->kind = COMPLETION_NO_MATCH;
            free(decoded_basename);
            return 0;
        }
    }
    append_delimiter = result->kind == COMPLETION_UNIQUE &&
                       (is_directory || *cursor == *line_len);
    insertion_status = completion_apply_insertion(
        line, capacity, line_len, cursor, replace_start, escaped_name,
        append_delimiter, scan.quote, is_directory);
    free(escaped_name);
    free(decoded_basename);
    if (insertion_status < 0) {
        completion_result_free(result);
        return -1;
    }
    if (insertion_status == 0) {
        completion_result_free(result);
        result->kind = COMPLETION_NO_MATCH;
        return 0;
    }
    result->line_changed = true;
    return 0;
}

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

static void ls_request_init(struct ls_request *request)
{
    request->options.long_format = false;
    request->options.show_all = false;
    request->options.recursive = false;
    request->options.human_readable = false;
    request->options.sort_key = LS_SORT_NAME;
    request->paths = NULL;
    request->path_count = 0;
}

static void ls_request_free(struct ls_request *request)
{
    if (request == NULL) {
        return;
    }
    free(request->paths);
    ls_request_init(request);
}

static void ls_output_init(struct ls_output *output)
{
    output->stdout_failed = 0;
    output->stdout_failure_reported = 0;
    output->output_started = 0;
}

static bool ls_ancestor_contains(const struct ls_ancestor *ancestor,
                                 dev_t st_dev,
                                 ino_t st_ino)
{
    while (ancestor != NULL) {
        if (ancestor->st_dev == st_dev && ancestor->st_ino == st_ino) {
            return true;
        }
        ancestor = ancestor->parent;
    }
    return false;
}

static void ls_report_stdout_failure(struct ls_output *output)
{
    static const char message[] = "ls: stdout write failed\n";
    ssize_t written;

    output->stdout_failed = 1;
    if (output->stdout_failure_reported) {
        return;
    }
    output->stdout_failure_reported = 1;
    do {
        written = write(STDERR_FILENO, message, sizeof(message) - 1);
    } while (written < 0 && errno == EINTR);
}

static int ls_write_stdout(struct ls_output *output,
                           const void *buffer,
                           size_t buffer_len)
{
    const unsigned char *cursor = (const unsigned char *)buffer;

    while (buffer_len > 0) {
        ssize_t written = write(STDOUT_FILENO, cursor, buffer_len);

        if (written < 0) {
            if (errno == EINTR) {
                continue;
            }
            ls_report_stdout_failure(output);
            return -1;
        }
        if (written == 0) {
            errno = EIO;
            ls_report_stdout_failure(output);
            return -1;
        }
        cursor += written;
        buffer_len -= (size_t)written;
    }
    return 0;
}

static int ls_write_stdout_text(struct ls_output *output, const char *text)
{
    return ls_write_stdout(output, text, strlen(text));
}

static int parse_ls_request(const struct tokens *tokens, struct ls_request *request)
{
    size_t i;
    bool end_options = false;

    ls_request_init(request);
    for (i = 1; i < tokens->argc; ++i) {
        const char *token = tokens->argv[i];
        const char *option;
        const char **new_paths;

        if (end_options || token[0] != '-' || token[1] == '\0') {
            if (request->path_count == (size_t)-1 ||
                request->path_count + 1 >
                    (size_t)-1 / sizeof(request->paths[0])) {
                fprintf(stderr, "ls: out of memory\n");
                return 1;
            }
            new_paths = (const char **)realloc(
                request->paths,
                (request->path_count + 1) * sizeof(request->paths[0]));
            if (new_paths == NULL) {
                fprintf(stderr, "ls: out of memory\n");
                return 1;
            }
            request->paths = new_paths;
            request->paths[request->path_count++] = token;
            continue;
        }

        if (strcmp(token, "--") == 0) {
            end_options = true;
            continue;
        }

        for (option = token + 1; *option != '\0'; ++option) {
            switch (*option) {
            case 'l':
                request->options.long_format = true;
                break;
            case 'a':
                request->options.show_all = true;
                break;
            case 'R':
                request->options.recursive = true;
                break;
            case 't':
                request->options.sort_key = LS_SORT_MTIME;
                break;
            case 'S':
                request->options.sort_key = LS_SORT_SIZE;
                break;
            case 'h':
                request->options.human_readable = true;
                break;
            default:
                fprintf(stderr, "ls: invalid option -- '%c'\n"
                                "usage: ls [-laRtSh] [--] [path ...]\n",
                        *option);
                return 2;
            }
        }
    }

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
    out[3] = (mode & S_ISUID) ? ((mode & S_IXUSR) ? 's' : 'S') :
             ((mode & S_IXUSR) ? 'x' : '-');
    out[4] = (mode & S_IRGRP) ? 'r' : '-';
    out[5] = (mode & S_IWGRP) ? 'w' : '-';
    out[6] = (mode & S_ISGID) ? ((mode & S_IXGRP) ? 's' : 'S') :
             ((mode & S_IXGRP) ? 'x' : '-');
    out[7] = (mode & S_IROTH) ? 'r' : '-';
    out[8] = (mode & S_IWOTH) ? 'w' : '-';
    out[9] = (mode & S_ISVTX) ? ((mode & S_IXOTH) ? 't' : 'T') :
             ((mode & S_IXOTH) ? 'x' : '-');
    out[10] = '\0';
}

static void ls_entry_list_init(struct ls_entry_list *list)
{
    list->items = NULL;
    list->count = 0;
    list->capacity = 0;
}

static void ls_entry_list_free(struct ls_entry_list *list)
{
    size_t i;

    if (list == NULL) {
        return;
    }
    for (i = 0; i < list->count; ++i) {
        free(list->items[i].name);
        free(list->items[i].full_path);
    }
    free(list->items);
    ls_entry_list_init(list);
}

static int ls_entry_list_append(struct ls_entry_list *list,
                                char *name,
                                char *full_path,
                                const struct stat *st)
{
    struct ls_entry *new_items;
    size_t new_capacity;

    if (list->count == list->capacity) {
        new_capacity = list->capacity == 0 ? 16 : list->capacity * 2;
        if (new_capacity < list->capacity ||
            new_capacity > (size_t)-1 / sizeof(list->items[0])) {
            errno = ENOMEM;
            return -1;
        }
        new_items = (struct ls_entry *)realloc(
            list->items, new_capacity * sizeof(list->items[0]));
        if (new_items == NULL) {
            return -1;
        }
        list->items = new_items;
        list->capacity = new_capacity;
    }

    list->items[list->count].name = name;
    list->items[list->count].full_path = full_path;
    list->items[list->count].st = *st;
    ++list->count;
    return 0;
}

static char *ls_join_path(const char *directory, const char *name)
{
    size_t directory_len;
    size_t name_len;
    size_t separator_len;
    char *full_path;

    directory_len = strlen(directory);
    name_len = strlen(name);
    separator_len = directory_len > 0 && directory[directory_len - 1] == '/' ? 0 : 1;
    if (directory_len > (size_t)-1 - separator_len ||
        directory_len + separator_len > (size_t)-1 - name_len ||
        directory_len + separator_len + name_len == (size_t)-1) {
        errno = ENAMETOOLONG;
        return NULL;
    }

    full_path = (char *)malloc(directory_len + separator_len + name_len + 1);
    if (full_path == NULL) {
        return NULL;
    }
    memcpy(full_path, directory, directory_len);
    if (separator_len != 0) {
        full_path[directory_len] = '/';
    }
    memcpy(full_path + directory_len + separator_len, name, name_len + 1);
    return full_path;
}

static int collect_directory(const char *path,
                             const struct ls_options *options,
                             struct ls_entry_list *list)
{
    DIR *directory;
    struct dirent *entry;
    int status = 0;
    int read_error = 0;

    directory = opendir(path);
    if (directory == NULL) {
        fprintf(stderr, "ls: %s: %s\n", path, strerror(errno));
        return 1;
    }

    for (;;) {
        char *name;
        char *full_path;
        struct stat st;

        errno = 0;
        entry = readdir(directory);
        if (entry == NULL) {
            read_error = errno;
            break;
        }
        if (!options->show_all && entry->d_name[0] == '.') {
            continue;
        }

        name = strdup(entry->d_name);
        if (name == NULL) {
            fprintf(stderr, "ls: %s: out of memory\n", path);
            status = 1;
            break;
        }
        full_path = ls_join_path(path, entry->d_name);
        if (full_path == NULL) {
            if (errno == ENAMETOOLONG) {
                fprintf(stderr, "ls: path too long: %s/%s\n",
                        path, entry->d_name);
            } else {
                fprintf(stderr, "ls: %s: out of memory\n", path);
            }
            free(name);
            status = 1;
            continue;
        }
        if (lstat(full_path, &st) < 0) {
            fprintf(stderr, "ls: %s: %s\n", full_path, strerror(errno));
            free(name);
            free(full_path);
            status = 1;
            continue;
        }
        if (ls_entry_list_append(list, name, full_path, &st) < 0) {
            fprintf(stderr, "ls: %s: out of memory\n", path);
            free(name);
            free(full_path);
            status = 1;
            break;
        }
    }
    if (read_error != 0) {
        fprintf(stderr, "ls: %s: %s\n", path, strerror(read_error));
        status = 1;
    }
    if (closedir(directory) < 0) {
        fprintf(stderr, "ls: %s: %s\n", path, strerror(errno));
        status = 1;
    }
    return status;
}

static enum ls_sort_key g_ls_sort_key;

static int compare_mtime(const struct stat *left, const struct stat *right)
{
    if (left->st_mtime > right->st_mtime) {
        return -1;
    }
    if (left->st_mtime < right->st_mtime) {
        return 1;
    }
#if LS_HAS_MTIME_NSEC
    if (left->st_mtim.tv_nsec > right->st_mtim.tv_nsec) {
        return -1;
    }
    if (left->st_mtim.tv_nsec < right->st_mtim.tv_nsec) {
        return 1;
    }
#endif
    return 0;
}

static int compare_ls_entries(const void *left_pointer, const void *right_pointer)
{
    const struct ls_entry *left = (const struct ls_entry *)left_pointer;
    const struct ls_entry *right = (const struct ls_entry *)right_pointer;

    if (g_ls_sort_key == LS_SORT_MTIME) {
        int mtime_order = compare_mtime(&left->st, &right->st);

        if (mtime_order != 0) {
            return mtime_order;
        }
    } else if (g_ls_sort_key == LS_SORT_SIZE) {
        if (left->st.st_size > right->st.st_size) {
            return -1;
        }
        if (left->st.st_size < right->st.st_size) {
            return 1;
        }
    }
    return strcmp(left->name, right->name);
}

static void format_human_size(off_t size, char output[64])
{
    static const char units[] = "BKMGTPE";
    uintmax_t value = size < 0 ? 0 : (uintmax_t)size;
    double scaled = (double)value;
    size_t unit_index = 0;

    while (scaled >= 1024.0 && unit_index + 1 < sizeof(units) - 1) {
        scaled /= 1024.0;
        ++unit_index;
    }
    if (scaled < 10.0) {
        snprintf(output, 64, "%.1f%c", scaled, units[unit_index]);
    } else {
        snprintf(output, 64, "%.0f%c", scaled, units[unit_index]);
    }
}

static void format_mtime(time_t mtime, char output[32])
{
    struct tm local_time;

    if (localtime_r(&mtime, &local_time) == NULL ||
        strftime(output, 32, "%Y-%m-%d %H:%M", &local_time) == 0) {
        snprintf(output, 32, "1970-01-01 00:00");
    }
}

static int print_symlink_target(const char *path, struct ls_output *output)
{
    char *target = NULL;
    size_t capacity = 128;

    for (;;) {
        char *new_target;
        ssize_t target_length;

        new_target = (char *)realloc(target, capacity);
        if (new_target == NULL) {
            free(target);
            fprintf(stderr, "ls: %s: out of memory\n", path);
            return 1;
        }
        target = new_target;
        target_length = readlink(path, target, capacity - 1);
        if (target_length < 0) {
            fprintf(stderr, "ls: %s: %s\n", path, strerror(errno));
            free(target);
            return 1;
        }
        if ((size_t)target_length < capacity - 1) {
            target[target_length] = '\0';
            if (ls_write_stdout_text(output, " -> ") != 0 ||
                ls_write_stdout_text(output, target) != 0) {
                free(target);
                return 1;
            }
            free(target);
            return 0;
        }
        if (capacity > (size_t)-1 / 2) {
            free(target);
            fprintf(stderr, "ls: %s: target path too long\n", path);
            return 1;
        }
        capacity *= 2;
    }
}

static int print_ls_entry(const struct ls_entry *entry,
                          const struct ls_options *options,
                          struct ls_output *output)
{
    if (!options->long_format) {
        return ls_write_stdout_text(output, entry->name) != 0 ||
                       ls_write_stdout_text(output, "\n") != 0
                   ? 1
                   : 0;
    }

    {
        char mode[11];
        char size[64];
        char mtime[32];
        int status = 0;

        format_mode(entry->st.st_mode, mode);
        if (options->human_readable) {
            format_human_size(entry->st.st_size, size);
        } else {
            snprintf(size, sizeof(size), "%jd", (intmax_t)entry->st.st_size);
        }
        format_mtime(entry->st.st_mtime, mtime);
        {
            char metadata[160];
            int metadata_length = snprintf(
                metadata,
                sizeof(metadata),
                "%s %" PRIuMAX " %" PRIuMAX " %" PRIuMAX " %s %s ",
                mode,
                (uintmax_t)entry->st.st_nlink,
                (uintmax_t)entry->st.st_uid,
                (uintmax_t)entry->st.st_gid,
                size,
                mtime);

            if (metadata_length < 0 ||
                (size_t)metadata_length >= sizeof(metadata) ||
                ls_write_stdout(output, metadata, (size_t)metadata_length) != 0 ||
                ls_write_stdout_text(output, entry->name) != 0) {
                return 1;
            }
        }
        if (S_ISLNK(entry->st.st_mode)) {
            status = print_symlink_target(entry->full_path, output);
        }
        if (status == 0 && ls_write_stdout_text(output, "\n") != 0) {
            status = 1;
        }
        return status;
    }
}

static int begin_ls_directory_section(const char *path,
                                      struct ls_output *output)
{
    if (output->output_started &&
        ls_write_stdout_text(output, "\n") != 0) {
        return 1;
    }
    if (ls_write_stdout_text(output, path) != 0 ||
        ls_write_stdout_text(output, ":\n") != 0) {
        return 1;
    }
    output->output_started = 1;
    return 0;
}

static int render_ls_directory(const char *path,
                               const struct stat *directory_stat,
                               const struct ls_options *options,
                               struct ls_output *output,
                               bool print_header,
                               const struct ls_ancestor *ancestors)
{
    struct ls_entry_list entries;
    struct ls_ancestor current_ancestor;
    size_t i;
    int status;

    if (print_header && begin_ls_directory_section(path, output) != 0) {
        return 1;
    }

    ls_entry_list_init(&entries);
    status = collect_directory(path, options, &entries);
    g_ls_sort_key = options->sort_key;
    if (entries.count > 1) {
        qsort(entries.items, entries.count, sizeof(entries.items[0]),
              compare_ls_entries);
    }
    for (i = 0; i < entries.count; ++i) {
        if (print_ls_entry(&entries.items[i], options, output) != 0) {
            status = 1;
            break;
        }
    }

    if (options->recursive) {
        current_ancestor.st_dev = directory_stat->st_dev;
        current_ancestor.st_ino = directory_stat->st_ino;
        current_ancestor.parent = ancestors;
        for (i = 0; i < entries.count; ++i) {
            const struct ls_entry *entry = &entries.items[i];

            if (!S_ISDIR(entry->st.st_mode) ||
                strcmp(entry->name, ".") == 0 ||
                strcmp(entry->name, "..") == 0) {
                continue;
            }
            if (ls_ancestor_contains(&current_ancestor,
                                     entry->st.st_dev,
                                     entry->st.st_ino)) {
                fprintf(stderr,
                        "ls: %s: recursive directory loop\n",
                        entry->full_path);
                status = 1;
                continue;
            }
            if (render_ls_directory(entry->full_path,
                                    &entry->st,
                                    options,
                                    output,
                                    true,
                                    &current_ancestor) != 0) {
                status = 1;
            }
        }
    }

    ls_entry_list_free(&entries);
    return status;
}

static int render_ls_operand(const char *path,
                             const struct ls_options *options,
                             struct ls_output *output,
                             bool print_recursive_root_header)
{
    struct stat st;

    if (lstat(path, &st) < 0) {
        fprintf(stderr, "ls: %s: %s\n", path, strerror(errno));
        return 1;
    }

    if (!S_ISDIR(st.st_mode)) {
        struct ls_entry entry = {(char *)path, (char *)path, st};
        return print_ls_entry(&entry, options, output);
    }

    return render_ls_directory(path,
                               &st,
                               options,
                               output,
                               options->recursive && print_recursive_root_header,
                               NULL);
}

static int run_ls(const struct tokens *tokens)
{
    struct ls_request request;
    const char *default_path = ".";
    size_t i;
    int parse_status;
    int status = 0;
    struct ls_output output;

    ls_request_init(&request);
    ls_output_init(&output);
    parse_status = parse_ls_request(tokens, &request);
    if (parse_status != 0) {
        ls_request_free(&request);
        return parse_status;
    }

    if (request.path_count == 0) {
        request.paths = &default_path;
        request.path_count = 1;
    }
    for (i = 0; i < request.path_count; ++i) {
        if (request.path_count > 1) {
            if (ls_write_stdout_text(&output, request.paths[i]) != 0 ||
                ls_write_stdout_text(&output, ":\n") != 0) {
                status = 1;
                break;
            }
            output.output_started = 1;
        }
        if (render_ls_operand(request.paths[i],
                              &request.options,
                              &output,
                              request.path_count == 1) != 0) {
            status = 1;
        }
        if (i + 1 < request.path_count) {
            if (ls_write_stdout_text(&output, "\n") != 0) {
                status = 1;
                break;
            }
        }
    }
    if (request.paths == &default_path) {
        request.paths = NULL;
    }
    ls_request_free(&request);
    return status;
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
    puts("  exec CMD [args ...]  Replace mini shell with CMD on the same PTY");
    puts("  run CMD [args ...]   Try an external exec (currently blocked here)");
    puts("  clear                Clear the terminal");
    puts("  exit | quit          Leave the shell");
    puts("");
    puts("Note: this install_recovery shell cannot currently exec follow-on binaries.");
}

static void build_prompt(char *buffer, size_t buffer_len)
{
    char cwd[PATH_MAX];

    if (getcwd(cwd, sizeof(cwd)) == NULL) {
        snprintf(cwd, sizeof(cwd), "?");
    }
    snprintf(buffer, buffer_len, "root@SM-T377A:%s# ", cwd);
}

static void restore_terminal_mode(void)
{
    if (g_termios_saved) {
        tcsetattr(STDIN_FILENO, TCSANOW, &g_saved_termios);
    }
}

static int enable_line_editor_mode(void)
{
    struct termios raw;

    if (!isatty(STDIN_FILENO)) {
        return 0;
    }
    if (tcgetattr(STDIN_FILENO, &g_saved_termios) < 0) {
        return -1;
    }
    raw = g_saved_termios;
    raw.c_lflag &= ~(ICANON | ECHO);
    raw.c_cc[VMIN] = 1;
    raw.c_cc[VTIME] = 0;
    if (tcsetattr(STDIN_FILENO, TCSANOW, &raw) < 0) {
        return -1;
    }
    g_termios_saved = 1;
    return 0;
}

static int write_stdout_all(const char *text)
{
    return write_fd_all(STDOUT_FILENO, text, strlen(text));
}

static void redraw_input_line(const char *prompt, const char *line, size_t line_len, size_t cursor)
{
    char seq[64];
    size_t tail;

    write_stdout_all("\r\033[2K");
    write_stdout_all(prompt);
    write_fd_all(STDOUT_FILENO, line, line_len);
    tail = line_len - cursor;
    if (tail > 0) {
        snprintf(seq, sizeof(seq), "\033[%luD", (unsigned long)tail);
        write_stdout_all(seq);
    }
}

static void history_store(char history[][4096], size_t *history_count, const char *line)
{
    size_t i;

    if (line[0] == '\0') {
        return;
    }
    if (*history_count > 0 && strcmp(history[*history_count - 1], line) == 0) {
        return;
    }
    if (*history_count == 32) {
        for (i = 1; i < 32; ++i) {
            memcpy(history[i - 1], history[i], sizeof(history[i]));
        }
        *history_count = 31;
    }
    snprintf(history[*history_count], 4096, "%s", line);
    ++*history_count;
}

static int read_line_interactive(char *line, size_t line_size, const char *prompt)
{
    static char history[32][4096];
    static size_t history_count = 0;
    size_t history_index = history_count;
    size_t line_len = 0;
    size_t cursor = 0;

    if (!isatty(STDIN_FILENO)) {
        if (fgets(line, (int)line_size, stdin) == NULL) {
            return 0;
        }
        trim_newline(line);
        return 1;
    }

    if (enable_line_editor_mode() < 0) {
        if (fgets(line, (int)line_size, stdin) == NULL) {
            return 0;
        }
        trim_newline(line);
        return 1;
    }

    line[0] = '\0';
    write_stdout_all(prompt);

    for (;;) {
        unsigned char ch;
        ssize_t nread = read(STDIN_FILENO, &ch, 1);

        if (nread < 0) {
            if (errno == EINTR) {
                g_interrupted = 0;
                line_len = 0;
                cursor = 0;
                line[0] = '\0';
                write_stdout_all("\n");
                restore_terminal_mode();
                return 1;
            }
            restore_terminal_mode();
            return 0;
        }
        if (nread == 0) {
            restore_terminal_mode();
            return 0;
        }

        if (ch == '\r' || ch == '\n') {
            line[line_len] = '\0';
            write_stdout_all("\r\n");
            restore_terminal_mode();
            history_store(history, &history_count, line);
            return 1;
        }
        if (ch == 0x03) {
            line_len = 0;
            cursor = 0;
            line[0] = '\0';
            write_stdout_all("^C\r\n");
            restore_terminal_mode();
            return 1;
        }
        if (ch == 0x04) {
            restore_terminal_mode();
            if (line_len == 0) {
                write_stdout_all("\r\n");
                return 0;
            }
            continue;
        }
        if (ch == 0x01) {
            cursor = 0;
            redraw_input_line(prompt, line, line_len, cursor);
            continue;
        }
        if (ch == 0x05) {
            cursor = line_len;
            redraw_input_line(prompt, line, line_len, cursor);
            continue;
        }
        if (ch == 0x0c) {
            write_stdout_all("\033[2J\033[H");
            redraw_input_line(prompt, line, line_len, cursor);
            continue;
        }
        if (ch == 0x7f || ch == 0x08) {
            if (cursor > 0) {
                memmove(line + cursor - 1, line + cursor, line_len - cursor);
                --cursor;
                --line_len;
                line[line_len] = '\0';
                redraw_input_line(prompt, line, line_len, cursor);
            }
            continue;
        }
        if (ch == 0x1b) {
            unsigned char seq[3];
            ssize_t seq_len;

            seq_len = read(STDIN_FILENO, seq, 1);
            if (seq_len <= 0 || seq[0] != '[') {
                continue;
            }
            seq_len = read(STDIN_FILENO, seq + 1, 1);
            if (seq_len <= 0) {
                continue;
            }
            if (seq[1] == 'A') {
                if (history_count > 0 && history_index > 0) {
                    --history_index;
                    snprintf(line, line_size, "%s", history[history_index]);
                    line_len = strlen(line);
                    cursor = line_len;
                    redraw_input_line(prompt, line, line_len, cursor);
                }
                continue;
            }
            if (seq[1] == 'B') {
                if (history_index + 1 < history_count) {
                    ++history_index;
                    snprintf(line, line_size, "%s", history[history_index]);
                    line_len = strlen(line);
                } else {
                    history_index = history_count;
                    line_len = 0;
                    line[0] = '\0';
                }
                cursor = line_len;
                redraw_input_line(prompt, line, line_len, cursor);
                continue;
            }
            if (seq[1] == 'C') {
                if (cursor < line_len) {
                    ++cursor;
                    redraw_input_line(prompt, line, line_len, cursor);
                }
                continue;
            }
            if (seq[1] == 'D') {
                if (cursor > 0) {
                    --cursor;
                    redraw_input_line(prompt, line, line_len, cursor);
                }
                continue;
            }
            if (seq[1] == 'H') {
                cursor = 0;
                redraw_input_line(prompt, line, line_len, cursor);
                continue;
            }
            if (seq[1] == 'F') {
                cursor = line_len;
                redraw_input_line(prompt, line, line_len, cursor);
                continue;
            }
            if (seq[1] >= '0' && seq[1] <= '9') {
                if (read(STDIN_FILENO, seq + 2, 1) > 0 && seq[1] == '3' && seq[2] == '~' && cursor < line_len) {
                    memmove(line + cursor, line + cursor + 1, line_len - cursor - 1);
                    --line_len;
                    line[line_len] = '\0';
                    redraw_input_line(prompt, line, line_len, cursor);
                }
                continue;
            }
            continue;
        }
        if (isprint(ch) && line_len + 1 < line_size) {
            memmove(line + cursor + 1, line + cursor, line_len - cursor);
            line[cursor] = (char)ch;
            ++cursor;
            ++line_len;
            line[line_len] = '\0';
            redraw_input_line(prompt, line, line_len, cursor);
        }
    }
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

static int exec_external(struct tokens *tokens)
{
    signal(SIGINT, SIG_DFL);
    execvp(tokens->argv[1], &tokens->argv[1]);
    fprintf(stderr, "exec: %s: %s\n", tokens->argv[1], strerror(errno));
    mini_shell_install_signal_handlers();
    return errno == EACCES ? 126 : 127;
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
        return run_ls(tokens);
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
    if (strcmp(cmd, "exec") == 0) {
        if (tokens->argc < 2) {
            fputs("exec: missing command\n", stderr);
            return 1;
        }
        return exec_external(tokens);
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
    char prompt[PATH_MAX + 32];

    mini_shell_install_signal_handlers();
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    atexit(restore_terminal_mode);

    puts("[+] Mini root shell ready. Type 'help' for builtins.");
    print_id();

    for (;;) {
        struct tokens tokens;
        int rc;

        g_interrupted = 0;
        build_prompt(prompt, sizeof(prompt));
        if (!read_line_interactive(line, sizeof(line), prompt)) {
            if (g_interrupted || errno == EINTR) {
                clearerr(stdin);
                continue;
            }
            break;
        }
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
