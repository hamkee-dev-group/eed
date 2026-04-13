#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <fcntl.h>
#include <regex.h>
#include <errno.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <signal.h>
#include <limits.h>

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <openssl/core_names.h>
#include <openssl/opensslv.h>
#include <openssl/provider.h>

#if OPENSSL_VERSION_NUMBER < 0x30500000L
#error "eed requires OpenSSL 3.5.0 or newer for Argon2id support"
#endif

#define MAX_LINES 16384
#define MAX_LINE_LEN 1024
#define MAX_PASSWORD_LEN 1024
#define SALT_LEN 16
#define NONCE_LEN 12
#define KEY_LEN 32
#define TAG_LEN 16
#define HASH_LEN 32

#define FILE_MAGIC_LEN 4
#define FILE_HEADER_LEN (FILE_MAGIC_LEN + 1 + 1 + 1 + 1 + 4 + 4 + 4 + SALT_LEN + NONCE_LEN)
#define MIN_FILE_SIZE (FILE_HEADER_LEN + TAG_LEN)
#define MAX_PLAINTEXT_SIZE ((size_t)MAX_LINES * MAX_LINE_LEN)
#define MAX_CIPHERTEXT_SIZE (MAX_PLAINTEXT_SIZE)

#define FILE_VERSION 1U
#define KDF_ID_ARGON2ID 1U
#define CIPHER_ID_AES_256_GCM 1U
#define HEADER_FLAGS_NONE 0U

#define DEFAULT_ARGON2_MEMCOST_KIB 65536U
#define DEFAULT_ARGON2_ITERATIONS 3U
#define DEFAULT_ARGON2_LANES 1U
#define DEFAULT_ARGON2_VERSION 19U
#define RECOVERY_MAGIC_LEN 4
#define RECOVERY_HEADER_LEN (RECOVERY_MAGIC_LEN + HASH_LEN)
enum save_status
{
    SAVE_REOPEN_FAILED = -1,
    SAVE_FAILED = 0,
    SAVE_OK = 1
};

char *lines[MAX_LINES];
size_t line_count = 0;
char password[MAX_PASSWORD_LEN];
uint32_t current_argon2_memcost_kib = DEFAULT_ARGON2_MEMCOST_KIB;
uint32_t current_argon2_iterations = DEFAULT_ARGON2_ITERATIONS;
uint32_t current_argon2_lanes = DEFAULT_ARGON2_LANES;
dev_t current_file_dev = 0;
ino_t current_file_ino = 0;
unsigned char current_committed_hash[HASH_LEN];
int current_buffer_dirty = 0;
int current_loaded_from_backup = 0;
int current_recovery_valid = 1;

static volatile sig_atomic_t terminate_signal = 0;
static const unsigned char FILE_MAGIC[FILE_MAGIC_LEN] = {'E', 'E', 'D', '4'};
static const unsigned char RECOVERY_MAGIC[RECOVERY_MAGIC_LEN] = {'E', 'D', 'R', '1'};

static int load_default_provider(void);
static void handle_termination_signal(int sig);
static int install_signal_handlers(void);
static int lock_process_memory(void);
static int validate_argon2_params(uint32_t memcost_kib, uint32_t iterations, uint32_t lanes);
static int derive_key(const unsigned char *salt, uint32_t memcost_kib, uint32_t iterations, uint32_t lanes,
                      unsigned char *key);
static int compute_sha256_file(FILE *f, unsigned char *digest);
static void encode_u32_be(unsigned char *out, uint32_t value);
static uint32_t decode_u32_be(const unsigned char *in);
static int parse_fixed_hex(const char *text, unsigned char *out, size_t outlen);
static void build_file_header(unsigned char *header, const unsigned char *salt, const unsigned char *nonce,
                              uint32_t memcost_kib, uint32_t iterations, uint32_t lanes);
static int parse_file_header(const unsigned char *header, unsigned char *salt, unsigned char *nonce,
                             uint32_t *memcost_kib, uint32_t *iterations, uint32_t *lanes);
static void build_recovery_header(unsigned char *header, const unsigned char *base_hash);
static int parse_recovery_header(const unsigned char *header, unsigned char *base_hash);
static char *make_sidecar_path(const char *path, const char *suffix);
static char *directory_path_from_file_path(const char *path);
static int parent_directory_is_trusted(const char *path);
static int open_existing_regular_file(const char *path, FILE **file_out, struct stat *st_out);
static int copy_stream(FILE *src, FILE *dst);
static int replace_sidecar_from_stream(const char *path, const char *suffix, FILE *src);
static int remove_sidecar_if_exists(const char *path, const char *suffix);
static int write_recovery_snapshot(const char *path);
static int load_recovery_snapshot(const char *path, const unsigned char *expected_base_hash);
static int load_backup_snapshot(const char *path);
static int recover_from_backup_chain(const char *path, int *recovery_loaded);
static int open_editor_file(const char *path, FILE **file_out, struct stat *st_out);
static void update_open_file_identity(const struct stat *st);
static int path_matches_open_file(const char *path);
static int sync_parent_directory(const char *path);
static int append_loaded_byte(unsigned char byte, char **dest_lines, size_t *dest_line_count,
                              char **line, size_t *linelen);
static void discard_rest_of_line(void);
static int read_buffer_line(char *buf, size_t buflen);
static int secure_get_password(const char *prompt, char *buf, size_t buflen);
static int prompt_line_number(const char *prompt, size_t *value);
static int buffer_changed(const char *path);
static int can_modify_buffer(void);
static int ensure_recoverable_state_for_exit(const char *path);
static void clear_buffer_lines(void);
void secure_cleanup(void);
int load_encrypted(FILE *f);
static int write_encrypted(FILE *f);
static int save_encrypted_atomic(const char *path, FILE **file);
static int load_encrypted_from_offset(FILE *f, long start_offset);

static int load_default_provider(void)
{
    OSSL_PROVIDER *provider = OSSL_PROVIDER_load(NULL, "default");
    return (provider != NULL) ? 1 : 0;
}

static void handle_termination_signal(int sig)
{
    terminate_signal = sig;
}

static int install_signal_handlers(void)
{
    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_termination_signal;
    if (sigemptyset(&sa.sa_mask) == -1)
    {
        perror("sigemptyset");
        return 0;
    }
    if (sigaction(SIGINT, &sa, NULL) == -1 || sigaction(SIGTERM, &sa, NULL) == -1)
    {
        perror("sigaction");
        return 0;
    }
    return 1;
}

static int lock_process_memory(void)
{
    const char *require_mlock = getenv("EED_REQUIRE_MLOCK");

    if (mlockall(MCL_CURRENT | MCL_FUTURE) == 0)
    {
        return 1;
    }

    if (require_mlock && require_mlock[0] != '\0' && strcmp(require_mlock, "0") != 0)
    {
        perror("mlockall");
        return 0;
    }

    fprintf(stderr, "WARNING: mlockall unavailable; continuing without locked memory.\n");
    return 1;
}

static int validate_argon2_params(uint32_t memcost_kib, uint32_t iterations, uint32_t lanes)
{
    if (memcost_kib != DEFAULT_ARGON2_MEMCOST_KIB ||
        iterations != DEFAULT_ARGON2_ITERATIONS ||
        lanes != DEFAULT_ARGON2_LANES)
    {
        return 0;
    }
    return 1;
}

static int derive_key(const unsigned char *salt, uint32_t memcost_kib, uint32_t iterations, uint32_t lanes,
                      unsigned char *key)
{
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *ctx = NULL;
    unsigned int memcost_u;
    unsigned int iterations_u;
    unsigned int lanes_u;
    unsigned int threads_u;
    unsigned int version_u;
    OSSL_PARAM params[8];
    size_t param_count = 0;
    int ok = 0;

    if (!validate_argon2_params(memcost_kib, iterations, lanes))
    {
        fprintf(stderr, "ERROR: Unsupported Argon2id parameters.\n");
        goto cleanup;
    }
    if (memcost_kib > UINT_MAX || iterations > UINT_MAX || lanes > UINT_MAX)
    {
        fprintf(stderr, "ERROR: Argon2id parameters are out of range.\n");
        goto cleanup;
    }

    memcost_u = (unsigned int)memcost_kib;
    iterations_u = (unsigned int)iterations;
    lanes_u = (unsigned int)lanes;
    threads_u = lanes_u;
    version_u = DEFAULT_ARGON2_VERSION;

    kdf = EVP_KDF_fetch(NULL, "ARGON2ID", NULL);
    if (kdf == NULL)
    {
        fprintf(stderr, "ERROR: Argon2id KDF is unavailable.\n");
        goto cleanup;
    }

    ctx = EVP_KDF_CTX_new(kdf);
    if (ctx == NULL)
    {
        fprintf(stderr, "ERROR: EVP_KDF_CTX_new failed.\n");
        goto cleanup;
    }

    params[param_count++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD,
                                                              (void *)password,
                                                              strnlen(password, sizeof(password)));
    params[param_count++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
                                                              (void *)salt,
                                                              SALT_LEN);
    params[param_count++] = OSSL_PARAM_construct_uint(OSSL_KDF_PARAM_ITER, &iterations_u);
    params[param_count++] = OSSL_PARAM_construct_uint(OSSL_KDF_PARAM_ARGON2_LANES, &lanes_u);
    params[param_count++] = OSSL_PARAM_construct_uint(OSSL_KDF_PARAM_THREADS, &threads_u);
    params[param_count++] = OSSL_PARAM_construct_uint(OSSL_KDF_PARAM_ARGON2_MEMCOST, &memcost_u);
    params[param_count++] = OSSL_PARAM_construct_uint(OSSL_KDF_PARAM_ARGON2_VERSION, &version_u);
    params[param_count] = OSSL_PARAM_construct_end();

    if (EVP_KDF_derive(ctx, key, KEY_LEN, params) != 1)
    {
        fprintf(stderr, "ERROR: Argon2id key derivation failed.\n");
        goto cleanup;
    }

    ok = 1;

cleanup:
    if (ctx != NULL)
    {
        EVP_KDF_CTX_free(ctx);
    }
    if (kdf != NULL)
    {
        EVP_KDF_free(kdf);
    }
    return ok;
}

static int compute_sha256_file(FILE *f, unsigned char *digest)
{
    EVP_MD_CTX *ctx = NULL;
    unsigned int digest_len = 0U;
    unsigned char buf[4096];
    ssize_t bytes_read;
    int fd_copy = -1;
    int ok = 0;

    fd_copy = dup(fileno(f));
    if (fd_copy == -1)
    {
        perror("dup");
        return 0;
    }
    if (lseek(fd_copy, 0L, SEEK_SET) == (off_t)-1)
    {
        perror("lseek");
        close(fd_copy);
        return 0;
    }

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL)
    {
        fprintf(stderr, "ERROR: EVP_MD_CTX_new failed.\n");
        goto cleanup;
    }
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1)
    {
        fprintf(stderr, "ERROR: EVP_DigestInit_ex failed.\n");
        goto cleanup;
    }

    while ((bytes_read = read(fd_copy, buf, sizeof(buf))) > 0)
    {
        if (EVP_DigestUpdate(ctx, buf, (size_t)bytes_read) != 1)
        {
            fprintf(stderr, "ERROR: EVP_DigestUpdate failed.\n");
            goto cleanup;
        }
    }
    if (bytes_read < 0)
    {
        perror("read");
        goto cleanup;
    }
    if (EVP_DigestFinal_ex(ctx, digest, &digest_len) != 1 || digest_len != HASH_LEN)
    {
        fprintf(stderr, "ERROR: EVP_DigestFinal_ex failed.\n");
        goto cleanup;
    }

    ok = 1;

cleanup:
    if (ctx != NULL)
    {
        EVP_MD_CTX_free(ctx);
    }
    if (fd_copy != -1)
    {
        close(fd_copy);
    }
    OPENSSL_cleanse(buf, sizeof(buf));
    return ok;
}

static void encode_u32_be(unsigned char *out, uint32_t value)
{
    out[0] = (unsigned char)(value >> 24);
    out[1] = (unsigned char)(value >> 16);
    out[2] = (unsigned char)(value >> 8);
    out[3] = (unsigned char)value;
}

static uint32_t decode_u32_be(const unsigned char *in)
{
    return ((uint32_t)in[0] << 24) |
           ((uint32_t)in[1] << 16) |
           ((uint32_t)in[2] << 8) |
           (uint32_t)in[3];
}

static int parse_fixed_hex(const char *text, unsigned char *out, size_t outlen)
{
    size_t i;

    if (strlen(text) != outlen * 2U)
    {
        return 0;
    }

    for (i = 0; i < outlen; i++)
    {
        unsigned int high;
        unsigned int low;
        unsigned char ch_high;
        unsigned char ch_low;

        ch_high = (unsigned char)text[i * 2U];
        ch_low = (unsigned char)text[i * 2U + 1U];

        if (ch_high >= '0' && ch_high <= '9')
        {
            high = (unsigned int)(ch_high - '0');
        }
        else if (ch_high >= 'a' && ch_high <= 'f')
        {
            high = (unsigned int)(ch_high - 'a' + 10U);
        }
        else if (ch_high >= 'A' && ch_high <= 'F')
        {
            high = (unsigned int)(ch_high - 'A' + 10U);
        }
        else
        {
            return 0;
        }

        if (ch_low >= '0' && ch_low <= '9')
        {
            low = (unsigned int)(ch_low - '0');
        }
        else if (ch_low >= 'a' && ch_low <= 'f')
        {
            low = (unsigned int)(ch_low - 'a' + 10U);
        }
        else if (ch_low >= 'A' && ch_low <= 'F')
        {
            low = (unsigned int)(ch_low - 'A' + 10U);
        }
        else
        {
            return 0;
        }

        out[i] = (unsigned char)((high << 4U) | low);
    }

    return 1;
}

static void build_file_header(unsigned char *header, const unsigned char *salt, const unsigned char *nonce,
                              uint32_t memcost_kib, uint32_t iterations, uint32_t lanes)
{
    memcpy(header, FILE_MAGIC, FILE_MAGIC_LEN);
    header[4] = FILE_VERSION;
    header[5] = KDF_ID_ARGON2ID;
    header[6] = CIPHER_ID_AES_256_GCM;
    header[7] = HEADER_FLAGS_NONE;
    encode_u32_be(header + 8, memcost_kib);
    encode_u32_be(header + 12, iterations);
    encode_u32_be(header + 16, lanes);
    memcpy(header + 20, salt, SALT_LEN);
    memcpy(header + 20 + SALT_LEN, nonce, NONCE_LEN);
}

static int parse_file_header(const unsigned char *header, unsigned char *salt, unsigned char *nonce,
                             uint32_t *memcost_kib, uint32_t *iterations, uint32_t *lanes)
{
    if (memcmp(header, FILE_MAGIC, FILE_MAGIC_LEN) != 0)
    {
        fprintf(stderr, "ERROR: Unsupported encrypted file format.\n");
        return 0;
    }
    if (header[4] != FILE_VERSION || header[5] != KDF_ID_ARGON2ID ||
        header[6] != CIPHER_ID_AES_256_GCM || header[7] != HEADER_FLAGS_NONE)
    {
        fprintf(stderr, "ERROR: Unsupported crypto parameters.\n");
        return 0;
    }

    *memcost_kib = decode_u32_be(header + 8);
    *iterations = decode_u32_be(header + 12);
    *lanes = decode_u32_be(header + 16);
    if (!validate_argon2_params(*memcost_kib, *iterations, *lanes))
    {
        fprintf(stderr, "ERROR: Unsupported Argon2id parameters.\n");
        return 0;
    }

    memcpy(salt, header + 20, SALT_LEN);
    memcpy(nonce, header + 20 + SALT_LEN, NONCE_LEN);
    return 1;
}

static void build_recovery_header(unsigned char *header, const unsigned char *base_hash)
{
    memcpy(header, RECOVERY_MAGIC, RECOVERY_MAGIC_LEN);
    memcpy(header + RECOVERY_MAGIC_LEN, base_hash, HASH_LEN);
}

static int parse_recovery_header(const unsigned char *header, unsigned char *base_hash)
{
    if (memcmp(header, RECOVERY_MAGIC, RECOVERY_MAGIC_LEN) != 0)
    {
        fprintf(stderr, "ERROR: Unsupported recovery snapshot format.\n");
        return 0;
    }
    memcpy(base_hash, header + RECOVERY_MAGIC_LEN, HASH_LEN);
    return 1;
}

static char *make_sidecar_path(const char *path, const char *suffix)
{
    size_t path_len = strlen(path);
    size_t suffix_len = strlen(suffix);
    char *full_path = malloc(path_len + suffix_len + 1);

    if (!full_path)
    {
        perror("malloc");
        return NULL;
    }

    memcpy(full_path, path, path_len);
    memcpy(full_path + path_len, suffix, suffix_len + 1);
    return full_path;
}

static char *directory_path_from_file_path(const char *path)
{
    const char *slash = strrchr(path, '/');
    char *dir_path = NULL;

    if (!slash)
    {
        dir_path = strdup(".");
    }
    else if (slash == path)
    {
        dir_path = strdup("/");
    }
    else
    {
        size_t dir_len = (size_t)(slash - path);

        dir_path = malloc(dir_len + 1);
        if (dir_path)
        {
            memcpy(dir_path, path, dir_len);
            dir_path[dir_len] = '\0';
        }
    }

    if (!dir_path)
    {
        perror("malloc");
    }
    return dir_path;
}

static int parent_directory_is_trusted(const char *path)
{
    char *dir_path = NULL;
    struct stat st;
    uid_t uid = geteuid();
    int ok = 0;

    dir_path = directory_path_from_file_path(path);
    if (!dir_path)
    {
        return 0;
    }

    if (stat(dir_path, &st) == -1)
    {
        perror("stat");
        goto cleanup;
    }
    if (!S_ISDIR(st.st_mode))
    {
        fprintf(stderr, "ERROR: Parent path is not a directory.\n");
        goto cleanup;
    }
    if (st.st_uid != uid || (st.st_mode & (S_IWGRP | S_IWOTH)) != 0)
    {
        fprintf(stderr, "ERROR: Parent directory must be owned by the current user and not writable by group or others.\n");
        goto cleanup;
    }

    ok = 1;

cleanup:
    free(dir_path);
    return ok;
}

static int open_editor_file(const char *path, FILE **file_out, struct stat *st_out)
{
    FILE *file = NULL;
    struct stat st;
    struct stat lst;
    int fd;
    int flags = O_RDWR | O_CREAT;

#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif

    if (!parent_directory_is_trusted(path))
    {
        return 0;
    }

    fd = open(path, flags, S_IRUSR | S_IWUSR);
    if (fd == -1)
    {
        if (errno == ELOOP)
        {
            fprintf(stderr, "ERROR: Symbolic links are not supported.\n");
        }
        else
        {
            perror("open");
        }
        return 0;
    }

    if (fstat(fd, &st) == -1)
    {
        perror("fstat");
        close(fd);
        return 0;
    }
    if (!S_ISREG(st.st_mode))
    {
        fprintf(stderr, "ERROR: Only regular files are supported.\n");
        close(fd);
        return 0;
    }
    if (st.st_nlink != 1)
    {
        fprintf(stderr, "ERROR: Files with multiple hard links are not supported.\n");
        close(fd);
        return 0;
    }
    if (lstat(path, &lst) == -1)
    {
        perror("lstat");
        close(fd);
        return 0;
    }
    if (S_ISLNK(lst.st_mode))
    {
        fprintf(stderr, "ERROR: Symbolic links are not supported.\n");
        close(fd);
        return 0;
    }
    if (!S_ISREG(lst.st_mode))
    {
        fprintf(stderr, "ERROR: Only regular files are supported.\n");
        close(fd);
        return 0;
    }
    if (lst.st_nlink != 1)
    {
        fprintf(stderr, "ERROR: Files with multiple hard links are not supported.\n");
        close(fd);
        return 0;
    }
    if (lst.st_dev != st.st_dev || lst.st_ino != st.st_ino)
    {
        fprintf(stderr, "ERROR: File path changed during open; refusing to proceed.\n");
        close(fd);
        return 0;
    }
    if (fchmod(fd, S_IRUSR | S_IWUSR) == -1)
    {
        perror("fchmod");
        close(fd);
        return 0;
    }

    file = fdopen(fd, "rb+");
    if (!file)
    {
        perror("fdopen");
        close(fd);
        return 0;
    }
    if (setvbuf(file, NULL, _IONBF, 0) != 0)
    {
        fprintf(stderr, "ERROR: setvbuf failed.\n");
        fclose(file);
        return 0;
    }

    *file_out = file;
    if (st_out)
    {
        *st_out = st;
    }
    return 1;
}

static int open_existing_regular_file(const char *path, FILE **file_out, struct stat *st_out)
{
    FILE *file = NULL;
    struct stat st;
    struct stat lst;
    int fd;
    int flags = O_RDONLY;

#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif

    fd = open(path, flags);
    if (fd == -1)
    {
        if (errno == ENOENT)
        {
            return 0;
        }
        if (errno == ELOOP)
        {
            fprintf(stderr, "ERROR: Symbolic links are not supported.\n");
        }
        else
        {
            perror("open");
        }
        return -1;
    }

    if (fstat(fd, &st) == -1)
    {
        perror("fstat");
        close(fd);
        return -1;
    }
    if (!S_ISREG(st.st_mode) || st.st_nlink != 1)
    {
        fprintf(stderr, "ERROR: Recovery or backup file is not a supported regular file.\n");
        close(fd);
        return -1;
    }
    if (lstat(path, &lst) == -1)
    {
        perror("lstat");
        close(fd);
        return -1;
    }
    if (!S_ISREG(lst.st_mode) || lst.st_nlink != 1 || lst.st_dev != st.st_dev || lst.st_ino != st.st_ino)
    {
        fprintf(stderr, "ERROR: Recovery or backup path changed during open.\n");
        close(fd);
        return -1;
    }

    file = fdopen(fd, "rb");
    if (file == NULL)
    {
        perror("fdopen");
        close(fd);
        return -1;
    }
    if (setvbuf(file, NULL, _IONBF, 0) != 0)
    {
        fprintf(stderr, "ERROR: setvbuf failed.\n");
        fclose(file);
        return -1;
    }

    *file_out = file;
    if (st_out != NULL)
    {
        *st_out = st;
    }
    return 1;
}

static void update_open_file_identity(const struct stat *st)
{
    current_file_dev = st->st_dev;
    current_file_ino = st->st_ino;
}

static int path_matches_open_file(const char *path)
{
    struct stat st;

    if (lstat(path, &st) == -1)
    {
        perror("lstat");
        return 0;
    }
    if (!S_ISREG(st.st_mode) || st.st_dev != current_file_dev || st.st_ino != current_file_ino)
    {
        fprintf(stderr, "ERROR: File path changed during editing; refusing to save.\n");
        return 0;
    }
    return 1;
}

static int sync_parent_directory(const char *path)
{
    char *dir_path = NULL;
    int dir_fd = -1;
    int ok = 0;

    dir_path = directory_path_from_file_path(path);
    if (!dir_path)
    {
        goto cleanup;
    }

#ifdef O_DIRECTORY
    dir_fd = open(dir_path, O_RDONLY | O_DIRECTORY);
#else
    dir_fd = open(dir_path, O_RDONLY);
#endif
    if (dir_fd == -1)
    {
        perror("open directory");
        goto cleanup;
    }
    if (fsync(dir_fd) == -1)
    {
        perror("fsync directory");
        goto cleanup;
    }

    ok = 1;

cleanup:
    if (dir_fd != -1)
    {
        close(dir_fd);
    }
    free(dir_path);
    return ok;
}

static int copy_stream(FILE *src, FILE *dst)
{
    unsigned char buf[4096];
    ssize_t bytes_read;
    int src_fd = -1;
    int ok = 0;

    src_fd = dup(fileno(src));
    if (src_fd == -1)
    {
        perror("dup");
        goto cleanup;
    }
    if (lseek(src_fd, 0L, SEEK_SET) == (off_t)-1)
    {
        perror("lseek");
        goto cleanup;
    }

    while ((bytes_read = read(src_fd, buf, sizeof(buf))) > 0)
    {
        if (fwrite(buf, 1, (size_t)bytes_read, dst) != (size_t)bytes_read)
        {
            fprintf(stderr, "ERROR: Failed to write sidecar file.\n");
            goto cleanup;
        }
    }
    if (bytes_read < 0)
    {
        perror("read");
        goto cleanup;
    }

    ok = 1;

cleanup:
    if (src_fd != -1)
    {
        close(src_fd);
    }
    OPENSSL_cleanse(buf, sizeof(buf));
    return ok;
}

static int replace_sidecar_from_stream(const char *path, const char *suffix, FILE *src)
{
    FILE *tmp_file = NULL;
    char *sidecar_path = NULL;
    char *tmp_path = NULL;
    int tmp_fd = -1;
    int renamed = 0;
    int ok = 0;

    if (!parent_directory_is_trusted(path))
    {
        return 0;
    }

    sidecar_path = make_sidecar_path(path, suffix);
    if (sidecar_path == NULL)
    {
        goto cleanup;
    }
    tmp_path = make_sidecar_path(sidecar_path, ".tmp.XXXXXX");
    if (tmp_path == NULL)
    {
        goto cleanup;
    }

    tmp_fd = mkstemp(tmp_path);
    if (tmp_fd == -1)
    {
        perror("mkstemp");
        goto cleanup;
    }
    if (fchmod(tmp_fd, S_IRUSR | S_IWUSR) == -1)
    {
        perror("fchmod");
        goto cleanup;
    }
    tmp_file = fdopen(tmp_fd, "w+b");
    if (tmp_file == NULL)
    {
        perror("fdopen");
        goto cleanup;
    }
    tmp_fd = -1;

    if (setvbuf(tmp_file, NULL, _IONBF, 0) != 0)
    {
        fprintf(stderr, "ERROR: setvbuf failed.\n");
        goto cleanup;
    }
    if (!copy_stream(src, tmp_file))
    {
        goto cleanup;
    }
    if (fflush(tmp_file) == EOF)
    {
        perror("fflush");
        goto cleanup;
    }
    if (fsync(fileno(tmp_file)) == -1)
    {
        perror("fsync");
        goto cleanup;
    }
    if (rename(tmp_path, sidecar_path) == -1)
    {
        perror("rename");
        goto cleanup;
    }
    renamed = 1;
    if (!sync_parent_directory(path))
    {
        fprintf(stderr, "ERROR: Parent directory sync failed after sidecar update.\n");
        goto cleanup;
    }

    ok = 1;

cleanup:
    if (tmp_file != NULL)
    {
        fclose(tmp_file);
    }
    if (tmp_fd != -1)
    {
        close(tmp_fd);
    }
    if (!renamed && tmp_path != NULL)
    {
        unlink(tmp_path);
    }
    free(tmp_path);
    free(sidecar_path);
    return ok;
}

static int remove_sidecar_if_exists(const char *path, const char *suffix)
{
    char *sidecar_path = NULL;
    int ok = 1;
    int removed = 0;

    sidecar_path = make_sidecar_path(path, suffix);
    if (sidecar_path == NULL)
    {
        return 0;
    }

    if (unlink(sidecar_path) == -1)
    {
        if (errno != ENOENT)
        {
            perror("unlink");
            ok = 0;
        }
    }
    else
    {
        removed = 1;
    }

    if (removed && !sync_parent_directory(path))
    {
        ok = 0;
    }

    free(sidecar_path);
    return ok;
}

static int write_recovery_snapshot(const char *path)
{
    FILE *tmp_file = NULL;
    char *recovery_path = NULL;
    char *tmp_path = NULL;
    unsigned char header[RECOVERY_HEADER_LEN];
    int tmp_fd = -1;
    int renamed = 0;
    int ok = 0;

    if (!parent_directory_is_trusted(path))
    {
        goto cleanup;
    }

    recovery_path = make_sidecar_path(path, ".recovery");
    if (recovery_path == NULL)
    {
        goto cleanup;
    }
    tmp_path = make_sidecar_path(recovery_path, ".tmp.XXXXXX");
    if (tmp_path == NULL)
    {
        goto cleanup;
    }

    tmp_fd = mkstemp(tmp_path);
    if (tmp_fd == -1)
    {
        perror("mkstemp");
        goto cleanup;
    }
    if (fchmod(tmp_fd, S_IRUSR | S_IWUSR) == -1)
    {
        perror("fchmod");
        goto cleanup;
    }
    tmp_file = fdopen(tmp_fd, "w+b");
    if (tmp_file == NULL)
    {
        perror("fdopen");
        goto cleanup;
    }
    tmp_fd = -1;

    if (setvbuf(tmp_file, NULL, _IONBF, 0) != 0)
    {
        fprintf(stderr, "ERROR: setvbuf failed.\n");
        goto cleanup;
    }

    build_recovery_header(header, current_committed_hash);
    if (fwrite(header, 1, sizeof(header), tmp_file) != sizeof(header))
    {
        fprintf(stderr, "ERROR: Failed to write recovery header.\n");
        goto cleanup;
    }
    if (!write_encrypted(tmp_file))
    {
        goto cleanup;
    }
    if (fflush(tmp_file) == EOF)
    {
        perror("fflush");
        goto cleanup;
    }
    if (fsync(fileno(tmp_file)) == -1)
    {
        perror("fsync");
        goto cleanup;
    }
    if (rename(tmp_path, recovery_path) == -1)
    {
        perror("rename");
        goto cleanup;
    }
    renamed = 1;
    if (!sync_parent_directory(path))
    {
        fprintf(stderr, "ERROR: Parent directory sync failed after recovery snapshot.\n");
        goto cleanup;
    }

    ok = 1;

cleanup:
    if (tmp_file != NULL)
    {
        fclose(tmp_file);
    }
    if (tmp_fd != -1)
    {
        close(tmp_fd);
    }
    if (!renamed && tmp_path != NULL)
    {
        unlink(tmp_path);
    }
    OPENSSL_cleanse(header, sizeof(header));
    free(tmp_path);
    free(recovery_path);
    return ok;
}

static int load_recovery_snapshot(const char *path, const unsigned char *expected_base_hash)
{
    FILE *file = NULL;
    unsigned char header[RECOVERY_HEADER_LEN];
    unsigned char base_hash[HASH_LEN];
    char *recovery_path = NULL;
    int opened;
    int loaded = 0;

    recovery_path = make_sidecar_path(path, ".recovery");
    if (recovery_path == NULL)
    {
        goto cleanup;
    }

    opened = open_existing_regular_file(recovery_path, &file, NULL);
    if (opened <= 0)
    {
        loaded = opened;
        goto cleanup;
    }

    if (fread(header, 1, sizeof(header), file) != sizeof(header))
    {
        fprintf(stderr, "ERROR: Could not read recovery snapshot header.\n");
        loaded = -1;
        goto cleanup;
    }
    if (!parse_recovery_header(header, base_hash))
    {
        loaded = -1;
        goto cleanup;
    }
    if (CRYPTO_memcmp(base_hash, expected_base_hash, HASH_LEN) != 0)
    {
        loaded = 0;
        goto cleanup;
    }

    if (!load_encrypted_from_offset(file, (long)RECOVERY_HEADER_LEN))
    {
        loaded = -1;
        goto cleanup;
    }
    loaded = 1;

cleanup:
    if (file != NULL)
    {
        fclose(file);
    }
    OPENSSL_cleanse(header, sizeof(header));
    OPENSSL_cleanse(base_hash, sizeof(base_hash));
    free(recovery_path);
    return loaded;
}

static int load_backup_snapshot(const char *path)
{
    FILE *file = NULL;
    char *backup_path = NULL;
    int opened;
    int loaded = 0;

    backup_path = make_sidecar_path(path, ".bak");
    if (backup_path == NULL)
    {
        goto cleanup;
    }

    opened = open_existing_regular_file(backup_path, &file, NULL);
    if (opened <= 0)
    {
        loaded = opened;
        goto cleanup;
    }

    if (!load_encrypted(file))
    {
        loaded = -1;
        goto cleanup;
    }

    if (!compute_sha256_file(file, current_committed_hash))
    {
        loaded = -1;
        goto cleanup;
    }
    current_loaded_from_backup = 1;
    current_buffer_dirty = 1;
    current_recovery_valid = 1;
    loaded = 1;

cleanup:
    if (file != NULL)
    {
        fclose(file);
    }
    free(backup_path);
    return loaded;
}

static int buffer_changed(const char *path)
{
    if (!write_recovery_snapshot(path))
    {
        current_buffer_dirty = 1;
        current_recovery_valid = 0;
        fprintf(stderr, "ERROR: Failed to update the encrypted recovery snapshot.\n");
        return 0;
    }

    current_buffer_dirty = 1;
    current_recovery_valid = 1;
    return 1;
}

static int recover_from_backup_chain(const char *path, int *recovery_loaded)
{
    int backup_status;
    int recovery_status;

    if (recovery_loaded != NULL)
    {
        *recovery_loaded = 0;
    }

    backup_status = load_backup_snapshot(path);
    if (backup_status <= 0)
    {
        return backup_status;
    }

    recovery_status = load_recovery_snapshot(path, current_committed_hash);
    if (recovery_status < 0)
    {
        return -1;
    }
    if (recovery_status == 1 && recovery_loaded != NULL)
    {
        *recovery_loaded = 1;
    }

    current_buffer_dirty = 1;
    current_recovery_valid = 1;
    return 1;
}

static int can_modify_buffer(void)
{
    if (current_buffer_dirty && !current_recovery_valid)
    {
        fprintf(stderr, "ERROR: Recovery snapshot is stale; save with 'w' before making more changes.\n");
        return 0;
    }
    return 1;
}

static int ensure_recoverable_state_for_exit(const char *path)
{
    if (!current_buffer_dirty || current_recovery_valid)
    {
        return 1;
    }

    if (write_recovery_snapshot(path))
    {
        current_recovery_valid = 1;
        printf("Saved an encrypted recovery snapshot for the latest unsaved changes.\n");
        return 1;
    }

    fprintf(stderr, "ERROR: Unsaved changes are not safely recoverable; write the file before exiting.\n");
    return 0;
}

static int append_loaded_byte(unsigned char byte, char **dest_lines, size_t *dest_line_count,
                              char **line, size_t *linelen)
{
    if (byte == '\0')
    {
        fprintf(stderr, "ERROR: File contains unsupported NUL bytes.\n");
        return 0;
    }

    if (*line == NULL)
    {
        *line = malloc(MAX_LINE_LEN);
        if (!*line)
        {
            perror("malloc");
            return 0;
        }
    }

    if (byte == '\n')
    {
        if (*dest_line_count >= MAX_LINES)
        {
            fprintf(stderr, "ERROR: File exceeds the maximum supported line count.\n");
            return 0;
        }

        (*line)[*linelen] = '\0';
        dest_lines[*dest_line_count] = *line;
        (*dest_line_count)++;
        *line = NULL;
        *linelen = 0;
        return 1;
    }

    if (*linelen >= MAX_LINE_LEN - 1)
    {
        fprintf(stderr, "ERROR: File contains a line longer than the supported limit.\n");
        return 0;
    }

    (*line)[(*linelen)++] = (char)byte;
    return 1;
}

static void discard_rest_of_line(void)
{
    int ch;

    while ((ch = getchar()) != '\n' && ch != EOF)
    {
    }
}

static int read_buffer_line(char *buf, size_t buflen)
{
    if (!fgets(buf, buflen, stdin))
    {
        return 0;
    }
    if (strchr(buf, '\n') == NULL)
    {
        discard_rest_of_line();
        fprintf(stderr, "ERROR: Input line exceeds the supported limit.\n");
        return -1;
    }

    buf[strcspn(buf, "\n")] = '\0';
    return 1;
}

static int secure_get_password(const char *prompt, char *buf, size_t buflen)
{
    struct termios old, new;
    int saved_errno = 0;

    printf("%s", prompt);
    fflush(stdout);
    if (tcgetattr(STDIN_FILENO, &old) == -1)
    {
        perror("tcgetattr");
        return 0;
    }

    new = old;
    new.c_lflag &= ~(ECHO);
    if (tcsetattr(STDIN_FILENO, TCSANOW, &new) == -1)
    {
        perror("tcsetattr");
        return 0;
    }

    errno = 0;
    if (!fgets(buf, buflen, stdin))
    {
        saved_errno = errno;
        tcsetattr(STDIN_FILENO, TCSANOW, &old);
        printf("\n");
        if (terminate_signal != 0 || saved_errno == EINTR)
        {
            fprintf(stderr, "Interrupted.\n");
        }
        else
        {
            fprintf(stderr, "Error reading password.\n");
        }
        return 0;
    }

    if (tcsetattr(STDIN_FILENO, TCSANOW, &old) == -1)
    {
        perror("tcsetattr");
        OPENSSL_cleanse(buf, buflen);
        return 0;
    }

    printf("\n");
    if (strchr(buf, '\n') == NULL)
    {
        discard_rest_of_line();
        OPENSSL_cleanse(buf, buflen);
        fprintf(stderr, "ERROR: Password exceeds the supported limit.\n");
        return 0;
    }

    buf[strcspn(buf, "\n")] = '\0';
    return 1;
}

static int prompt_line_number(const char *prompt, size_t *value)
{
    char buf[64];
    char *end = NULL;
    unsigned long long parsed;

    printf("%s", prompt);
    if (!fgets(buf, sizeof(buf), stdin))
    {
        fprintf(stderr, "Error reading input.\n");
        return 0;
    }
    if (strchr(buf, '\n') == NULL)
    {
        discard_rest_of_line();
        fprintf(stderr, "Invalid input.\n");
        return 0;
    }

    errno = 0;
    parsed = strtoull(buf, &end, 10);
    if (errno != 0 || end == buf)
    {
        fprintf(stderr, "Invalid input.\n");
        return 0;
    }

    while (*end == ' ' || *end == '\t')
    {
        end++;
    }
    if (*end != '\n' && *end != '\0')
    {
        fprintf(stderr, "Invalid input.\n");
        return 0;
    }
    if (parsed > SIZE_MAX)
    {
        fprintf(stderr, "Invalid input.\n");
        return 0;
    }

    *value = (size_t)parsed;
    return 1;
}

static void clear_buffer_lines(void)
{
    for (size_t i = 0; i < line_count; i++)
    {
        if (lines[i])
        {
            OPENSSL_cleanse(lines[i], strlen(lines[i]));
            free(lines[i]);
            lines[i] = NULL;
        }
    }
    line_count = 0;
}

void secure_cleanup(void)
{
    OPENSSL_cleanse(password, sizeof(password));
    clear_buffer_lines();
}

static int load_encrypted_from_offset(FILE *f, long start_offset)
{
    int ok = 0;
    uint32_t memcost_kib = 0;
    uint32_t iterations = 0;
    uint32_t lanes = 0;
    char *new_lines[MAX_LINES];
    size_t new_line_count = 0;
    unsigned char header[FILE_HEADER_LEN];
    unsigned char salt[SALT_LEN];
    unsigned char nonce[NONCE_LEN];
    unsigned char key[KEY_LEN];
    unsigned char *ciphertext = NULL;
    unsigned char tag[TAG_LEN];
    EVP_CIPHER_CTX *cipher_ctx = NULL;
    size_t ciphertext_len = 0;
    unsigned char outbuf[1024];
    int outlen = 0;
    char *line = NULL;
    size_t linelen = 0;
    size_t chunk_offset = 0;
    size_t chunk_size;
    size_t fsize;
    size_t encrypted_region_size;
    long ftellsize;

    memset(header, 0, sizeof(header));
    memset(salt, 0, sizeof(salt));
    memset(nonce, 0, sizeof(nonce));
    memset(key, 0, sizeof(key));
    memset(tag, 0, sizeof(tag));
    memset(outbuf, 0, sizeof(outbuf));
    memset(new_lines, 0, sizeof(new_lines));

    if (fseek(f, 0, SEEK_END) == -1)
    {
        perror("fseek");
        goto cleanup;
    }
    ftellsize = ftell(f);
    if (ftellsize == -1)
    {
        perror("ftell");
        goto cleanup;
    }
    fsize = (size_t)ftellsize;
    if (start_offset < 0L || (size_t)start_offset > fsize)
    {
        fprintf(stderr, "ERROR: Unsupported or malformed encrypted file.\n");
        goto cleanup;
    }
    encrypted_region_size = fsize - (size_t)start_offset;

    if (encrypted_region_size < MIN_FILE_SIZE || encrypted_region_size > FILE_HEADER_LEN + MAX_CIPHERTEXT_SIZE + TAG_LEN)
    {
        fprintf(stderr, "ERROR: Unsupported or malformed encrypted file.\n");
        goto cleanup;
    }
    if (fseek(f, start_offset, SEEK_SET) == -1)
    {
        perror("fseek");
        goto cleanup;
    }

    if (fread(header, 1, FILE_HEADER_LEN, f) != FILE_HEADER_LEN)
    {
        fprintf(stderr, "ERROR: Could not read file header.\n");
        goto cleanup;
    }
    if (!parse_file_header(header, salt, nonce, &memcost_kib, &iterations, &lanes))
    {
        goto cleanup;
    }

    ciphertext_len = encrypted_region_size - FILE_HEADER_LEN - TAG_LEN;
    if (ciphertext_len > MAX_CIPHERTEXT_SIZE)
    {
        fprintf(stderr, "ERROR: Unsupported or malformed encrypted file.\n");
        goto cleanup;
    }

    if (ciphertext_len != 0U)
    {
        ciphertext = malloc(ciphertext_len);
        if (!ciphertext)
        {
            perror("malloc");
            goto cleanup;
        }
    }
    if (ciphertext_len != 0U &&
        fread(ciphertext, 1, ciphertext_len, f) != ciphertext_len)
    {
        fprintf(stderr, "ERROR: Could not read encrypted payload.\n");
        goto cleanup;
    }
    if (fread(tag, 1, TAG_LEN, f) != TAG_LEN)
    {
        fprintf(stderr, "ERROR: Could not read AEAD tag.\n");
        goto cleanup;
    }

    if (!derive_key(salt, memcost_kib, iterations, lanes, key))
    {
        goto cleanup;
    }

    cipher_ctx = EVP_CIPHER_CTX_new();
    if (!cipher_ctx)
    {
        fprintf(stderr, "ERROR: EVP_CIPHER_CTX_new failed.\n");
        goto cleanup;
    }
    if (!EVP_DecryptInit_ex(cipher_ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
    {
        fprintf(stderr, "ERROR: EVP_DecryptInit_ex failed.\n");
        goto cleanup;
    }
    if (EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, NULL) != 1)
    {
        fprintf(stderr, "ERROR: EVP_CTRL_GCM_SET_IVLEN failed.\n");
        goto cleanup;
    }
    if (!EVP_DecryptInit_ex(cipher_ctx, NULL, NULL, key, nonce))
    {
        fprintf(stderr, "ERROR: EVP_DecryptInit_ex key/nonce failed.\n");
        goto cleanup;
    }
    if (!EVP_DecryptUpdate(cipher_ctx, NULL, &outlen, header, (int)sizeof(header)))
    {
        fprintf(stderr, "ERROR: EVP_DecryptUpdate AAD failed.\n");
        goto cleanup;
    }

    while (chunk_offset < ciphertext_len)
    {
        chunk_size = (ciphertext_len - chunk_offset > 1024) ? 1024 : (ciphertext_len - chunk_offset);
        if (!EVP_DecryptUpdate(cipher_ctx, outbuf, &outlen, ciphertext + chunk_offset, (int)chunk_size))
        {
            fprintf(stderr, "ERROR: EVP_DecryptUpdate failed.\n");
            goto cleanup;
        }
        chunk_offset += chunk_size;

        for (int i = 0; i < outlen; i++)
        {
            if (!append_loaded_byte(outbuf[i], new_lines, &new_line_count, &line, &linelen))
            {
                goto cleanup;
            }
        }
    }

    if (EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, tag) != 1)
    {
        fprintf(stderr, "ERROR: EVP_CTRL_GCM_SET_TAG failed.\n");
        goto cleanup;
    }
    if (!EVP_DecryptFinal_ex(cipher_ctx, outbuf, &outlen))
    {
        fprintf(stderr, "ERROR: EVP_DecryptFinal_ex failed.\n");
        goto cleanup;
    }
    for (int i = 0; i < outlen; i++)
    {
        if (!append_loaded_byte(outbuf[i], new_lines, &new_line_count, &line, &linelen))
        {
            goto cleanup;
        }
    }
    if (line != NULL || linelen != 0)
    {
        fprintf(stderr, "ERROR: Encrypted payload is malformed.\n");
        goto cleanup;
    }

    current_argon2_memcost_kib = memcost_kib;
    current_argon2_iterations = iterations;
    current_argon2_lanes = lanes;
    clear_buffer_lines();
    for (size_t i = 0; i < new_line_count; i++)
    {
        lines[i] = new_lines[i];
        new_lines[i] = NULL;
    }
    line_count = new_line_count;
    ok = 1;

cleanup:
    if (!ok)
    {
        for (size_t i = 0; i < new_line_count; i++)
        {
            if (new_lines[i] != NULL)
            {
                OPENSSL_cleanse(new_lines[i], strlen(new_lines[i]));
                free(new_lines[i]);
            }
        }
    }
    if (line)
    {
        OPENSSL_cleanse(line, MAX_LINE_LEN);
        free(line);
    }
    if (cipher_ctx)
    {
        EVP_CIPHER_CTX_free(cipher_ctx);
    }
    if (ciphertext)
    {
        OPENSSL_cleanse(ciphertext, ciphertext_len);
        free(ciphertext);
    }
    OPENSSL_cleanse(header, sizeof(header));
    OPENSSL_cleanse(salt, sizeof(salt));
    OPENSSL_cleanse(nonce, sizeof(nonce));
    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(tag, sizeof(tag));
    OPENSSL_cleanse(outbuf, sizeof(outbuf));
    return ok;
}

int load_encrypted(FILE *f)
{
    return load_encrypted_from_offset(f, 0L);
}

static int write_encrypted(FILE *f)
{
    int ok = 0;
    unsigned char header[FILE_HEADER_LEN];
    unsigned char salt[SALT_LEN];
    unsigned char nonce[NONCE_LEN];
    unsigned char key[KEY_LEN];
    unsigned char tag[TAG_LEN];
    EVP_CIPHER_CTX *cipher_ctx = NULL;
    size_t len = 0;
    int outlen;
    unsigned char inbuf[MAX_LINE_LEN], outbuf[MAX_LINE_LEN + EVP_MAX_BLOCK_LENGTH];
    const char *salt_hex = getenv("EED_TEST_SALT_HEX");
    const char *nonce_hex = getenv("EED_TEST_NONCE_HEX");

    memset(header, 0, sizeof(header));
    memset(salt, 0, sizeof(salt));
    memset(nonce, 0, sizeof(nonce));
    memset(key, 0, sizeof(key));
    memset(tag, 0, sizeof(tag));
    memset(inbuf, 0, sizeof(inbuf));
    memset(outbuf, 0, sizeof(outbuf));

    if ((salt_hex == NULL) != (nonce_hex == NULL))
    {
        fprintf(stderr, "ERROR: Deterministic test material requires both salt and nonce.\n");
        goto cleanup;
    }
    if (salt_hex != NULL)
    {
        if (!parse_fixed_hex(salt_hex, salt, sizeof(salt)) ||
            !parse_fixed_hex(nonce_hex, nonce, sizeof(nonce)))
        {
            fprintf(stderr, "ERROR: Invalid deterministic test salt or nonce.\n");
            goto cleanup;
        }
    }
    else if (RAND_bytes(salt, SALT_LEN) != 1 || RAND_bytes(nonce, NONCE_LEN) != 1)
    {
        fprintf(stderr, "ERROR: RAND_bytes failed.\n");
        goto cleanup;
    }
    if (!derive_key(salt,
                    current_argon2_memcost_kib,
                    current_argon2_iterations,
                    current_argon2_lanes,
                    key))
    {
        goto cleanup;
    }

    build_file_header(header,
                      salt,
                      nonce,
                      current_argon2_memcost_kib,
                      current_argon2_iterations,
                      current_argon2_lanes);
    if (fwrite(header, 1, sizeof(header), f) != sizeof(header))
    {
        fprintf(stderr, "ERROR: fwrite header failed.\n");
        goto cleanup;
    }

    cipher_ctx = EVP_CIPHER_CTX_new();
    if (!cipher_ctx)
    {
        fprintf(stderr, "ERROR: EVP_CIPHER_CTX_new failed.\n");
        goto cleanup;
    }
    if (!EVP_EncryptInit_ex(cipher_ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
    {
        fprintf(stderr, "ERROR: EVP_EncryptInit_ex failed.\n");
        goto cleanup;
    }
    if (EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, NULL) != 1)
    {
        fprintf(stderr, "ERROR: EVP_CTRL_GCM_SET_IVLEN failed.\n");
        goto cleanup;
    }
    if (!EVP_EncryptInit_ex(cipher_ctx, NULL, NULL, key, nonce))
    {
        fprintf(stderr, "ERROR: EVP_EncryptInit_ex key/nonce failed.\n");
        goto cleanup;
    }
    if (!EVP_EncryptUpdate(cipher_ctx, NULL, &outlen, header, (int)sizeof(header)))
    {
        fprintf(stderr, "ERROR: EVP_EncryptUpdate AAD failed.\n");
        goto cleanup;
    }

    for (size_t i = 0; i < line_count; i++)
    {
        len = strlen(lines[i]);
        if (len > MAX_LINE_LEN - 1)
        {
            fprintf(stderr, "ERROR: Buffer contains a line longer than the supported limit.\n");
            goto cleanup;
        }

        memset(inbuf, 0, sizeof(inbuf));
        memcpy(inbuf, lines[i], len);
        inbuf[len++] = '\n';

        if (!EVP_EncryptUpdate(cipher_ctx, outbuf, &outlen, inbuf, (int)len))
        {
            fprintf(stderr, "ERROR: EVP_EncryptUpdate failed.\n");
            goto cleanup;
        }
        if (fwrite(outbuf, 1, outlen, f) != (size_t)outlen)
        {
            fprintf(stderr, "ERROR: fwrite failed.\n");
            goto cleanup;
        }
        OPENSSL_cleanse(outbuf, sizeof(outbuf));
    }

    if (!EVP_EncryptFinal_ex(cipher_ctx, outbuf, &outlen))
    {
        fprintf(stderr, "ERROR: EVP_EncryptFinal_ex failed.\n");
        goto cleanup;
    }
    if (fwrite(outbuf, 1, outlen, f) != (size_t)outlen)
    {
        fprintf(stderr, "ERROR: fwrite final failed.\n");
        goto cleanup;
    }
    if (EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag) != 1)
    {
        fprintf(stderr, "ERROR: EVP_CTRL_GCM_GET_TAG failed.\n");
        goto cleanup;
    }
    if (fwrite(tag, 1, TAG_LEN, f) != TAG_LEN)
    {
        fprintf(stderr, "ERROR: fwrite AEAD tag failed.\n");
        goto cleanup;
    }

    ok = 1;

cleanup:
    if (cipher_ctx)
    {
        EVP_CIPHER_CTX_free(cipher_ctx);
    }
    OPENSSL_cleanse(header, sizeof(header));
    OPENSSL_cleanse(salt, sizeof(salt));
    OPENSSL_cleanse(nonce, sizeof(nonce));
    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(tag, sizeof(tag));
    OPENSSL_cleanse(inbuf, sizeof(inbuf));
    OPENSSL_cleanse(outbuf, sizeof(outbuf));
    return ok;
}

static int save_encrypted_atomic(const char *path, FILE **file)
{
    FILE *tmp_file = NULL;
    FILE *old_file = *file;
    struct stat old_st;
    struct stat st;
    char *tmp_path = NULL;
    int tmp_fd = -1;
    int renamed = 0;
    int status = SAVE_FAILED;

    if (!path_matches_open_file(path))
    {
        return SAVE_FAILED;
    }
    if (!parent_directory_is_trusted(path))
    {
        return SAVE_FAILED;
    }
    if (fstat(fileno(old_file), &old_st) == -1)
    {
        perror("fstat");
        return SAVE_FAILED;
    }

    tmp_path = make_sidecar_path(path, ".tmp.XXXXXX");
    if (!tmp_path)
    {
        return SAVE_FAILED;
    }

    tmp_fd = mkstemp(tmp_path);
    if (tmp_fd == -1)
    {
        perror("mkstemp");
        goto cleanup;
    }
    if (fchmod(tmp_fd, S_IRUSR | S_IWUSR) == -1)
    {
        perror("fchmod");
        goto cleanup;
    }
    if (flock(tmp_fd, LOCK_EX | LOCK_NB) == -1)
    {
        perror("flock");
        goto cleanup;
    }

    tmp_file = fdopen(tmp_fd, "w+b");
    if (!tmp_file)
    {
        perror("fdopen");
        goto cleanup;
    }
    tmp_fd = -1;

    if (setvbuf(tmp_file, NULL, _IONBF, 0) != 0)
    {
        fprintf(stderr, "ERROR: setvbuf failed.\n");
        goto cleanup;
    }
    if (!write_encrypted(tmp_file))
    {
        goto cleanup;
    }
    if (fflush(tmp_file) == EOF)
    {
        perror("fflush");
        goto cleanup;
    }
    if (fsync(fileno(tmp_file)) == -1)
    {
        perror("fsync");
        goto cleanup;
    }
    if (!parent_directory_is_trusted(path))
    {
        goto cleanup;
    }
    if (!path_matches_open_file(path))
    {
        goto cleanup;
    }

    if (!replace_sidecar_from_stream(path, ".bak", tmp_file))
    {
        fprintf(stderr, "ERROR: Failed to refresh the latest committed backup copy.\n");
        status = SAVE_REOPEN_FAILED;
        goto cleanup;
    }
    if (rename(tmp_path, path) == -1)
    {
        perror("rename");
        goto cleanup;
    }
    renamed = 1;
    if (!sync_parent_directory(path))
    {
        fprintf(stderr, "ERROR: Parent directory sync failed after save.\n");
        status = SAVE_REOPEN_FAILED;
        goto cleanup;
    }
    if (fstat(fileno(tmp_file), &st) == -1)
    {
        perror("fstat");
        status = SAVE_REOPEN_FAILED;
        goto cleanup;
    }
    if (!compute_sha256_file(tmp_file, current_committed_hash))
    {
        status = SAVE_REOPEN_FAILED;
        goto cleanup;
    }
    if (fclose(old_file) == EOF)
    {
        perror("fclose");
        fprintf(stderr, "ERROR: File was saved but the editor must exit to avoid stale writes.\n");
        old_file = NULL;
        status = SAVE_REOPEN_FAILED;
        goto cleanup;
    }
    old_file = NULL;

    *file = tmp_file;
    update_open_file_identity(&st);
    current_buffer_dirty = 0;
    current_loaded_from_backup = 0;
    current_recovery_valid = 1;
    if (!remove_sidecar_if_exists(path, ".recovery"))
    {
        fprintf(stderr, "WARNING: Could not remove the stale recovery snapshot.\n");
    }
    tmp_file = NULL;
    status = SAVE_OK;

cleanup:
    if (tmp_file)
    {
        fclose(tmp_file);
    }
    if (tmp_fd != -1)
    {
        close(tmp_fd);
    }
    if (!renamed && tmp_path)
    {
        unlink(tmp_path);
    }
    if (status == SAVE_REOPEN_FAILED)
    {
        if (old_file)
        {
            fclose(old_file);
        }
        *file = NULL;
    }
    free(tmp_path);
    return status;
}

static void print_buffer(void)
{
    for (size_t i = 0; i < line_count; i++)
    {
        printf("%zu: %s\n", i + 1, lines[i]);
    }
}

static int append_lines(const char *path)
{
    char buf[MAX_LINE_LEN];
    int read_status;
    int modified = 0;

    if (!can_modify_buffer())
    {
        return 0;
    }

    printf("Enter lines, single '.' on line to finish:\n");
    while ((read_status = read_buffer_line(buf, sizeof(buf))) != 0)
    {
        if (read_status < 0)
        {
            break;
        }
        if (strcmp(buf, ".") == 0)
        {
            break;
        }
        if (line_count >= MAX_LINES)
        {
            fprintf(stderr, "ERROR: Maximum line count reached.\n");
            break;
        }

        lines[line_count] = strdup(buf);
        if (!lines[line_count])
        {
            perror("strdup");
            break;
        }
        line_count++;
        modified = 1;
    }

    if (modified)
    {
        return buffer_changed(path);
    }
    return 0;
}

static int insert_lines(const char *path)
{
    size_t n;
    char buf[MAX_LINE_LEN];
    char *copy;
    int read_status;
    size_t insert_pos = 0;
    int modified = 0;

    if (!can_modify_buffer())
    {
        return 0;
    }

    if (!prompt_line_number("Insert before line number: ", &n))
    {
        return 0;
    }
    if (n < 1 || n > line_count + 1)
    {
        fprintf(stderr, "Invalid line number\n");
        return 0;
    }

    printf("Enter lines, single '.' on line to finish:\n");
    insert_pos = n - 1;
    while ((read_status = read_buffer_line(buf, sizeof(buf))) != 0)
    {
        if (read_status < 0)
        {
            break;
        }
        if (strcmp(buf, ".") == 0)
        {
            break;
        }
        if (line_count >= MAX_LINES)
        {
            fprintf(stderr, "ERROR: Maximum line count reached.\n");
            break;
        }

        copy = strdup(buf);
        if (!copy)
        {
            perror("strdup");
            break;
        }
        for (size_t i = line_count; i > insert_pos; i--)
        {
            lines[i] = lines[i - 1];
        }
        lines[insert_pos] = copy;
        insert_pos++;
        line_count++;
        modified = 1;
    }

    if (modified)
    {
        return buffer_changed(path);
    }
    return 0;
}

static int change_line(const char *path)
{
    char buf[MAX_LINE_LEN];
    char *copy;
    int read_status;
    size_t n;

    if (!can_modify_buffer())
    {
        return 0;
    }

    if (!prompt_line_number("Change line number: ", &n))
    {
        return 0;
    }
    if (n == 0 || n > line_count)
    {
        printf("Invalid line number\n");
        return 0;
    }

    printf("New line: ");
    read_status = read_buffer_line(buf, sizeof(buf));
    if (read_status <= 0)
    {
        return 0;
    }

    copy = strdup(buf);
    if (!copy)
    {
        perror("strdup");
        return 0;
    }
    OPENSSL_cleanse(lines[n - 1], strlen(lines[n - 1]));
    free(lines[n - 1]);
    lines[n - 1] = copy;
    return buffer_changed(path);
}

static int delete_line(const char *path)
{
    size_t n;

    if (!can_modify_buffer())
    {
        return 0;
    }

    if (!prompt_line_number("Delete line number: ", &n))
    {
        return 0;
    }
    if (n == 0 || n > line_count)
    {
        printf("Invalid line number\n");
        return 0;
    }

    OPENSSL_cleanse(lines[n - 1], strlen(lines[n - 1]));
    free(lines[n - 1]);
    for (size_t i = n - 1; i < line_count - 1; i++)
    {
        lines[i] = lines[i + 1];
    }
    lines[line_count - 1] = NULL;
    line_count--;
    return buffer_changed(path);
}

static void search_pattern(const char *pattern)
{
    regex_t regex;

    if (regcomp(&regex, pattern, REG_EXTENDED | REG_NOSUB) != 0)
    {
        printf("Invalid pattern\n");
        return;
    }
    for (size_t i = 0; i < line_count; i++)
    {
        if (regexec(&regex, lines[i], 0, NULL, 0) == 0)
        {
            printf("%zu: %s\n", i + 1, lines[i]);
        }
    }
    regfree(&regex);
}

static int substitute(const char *path, const char *old, const char *new)
{
    char buf[MAX_LINE_LEN];
    char *copy;
    size_t old_len;
    size_t new_len;
    char *pos;
    char *src;
    char *dst;
    size_t remaining;
    int modified = 0;

    if (!can_modify_buffer())
    {
        return 0;
    }

    old_len = strlen(old);
    new_len = strlen(new);
    if (old_len == 0)
    {
        fprintf(stderr, "ERROR: Empty substitutions are not allowed.\n");
        return 0;
    }

    for (size_t i = 0; i < line_count; i++)
    {
        src = lines[i];
        dst = buf;
        remaining = sizeof(buf) - 1;

        while ((pos = strstr(src, old)) != NULL)
        {
            size_t prefix_len = (size_t)(pos - src);

            if (prefix_len > remaining || new_len > remaining - prefix_len)
            {
                fprintf(stderr, "ERROR: Substitution would exceed the maximum line length.\n");
                goto finish;
            }

            memcpy(dst, src, prefix_len);
            dst += prefix_len;
            memcpy(dst, new, new_len);
            dst += new_len;
            remaining -= prefix_len + new_len;
            src = pos + old_len;
        }

        if (*src != '\0')
        {
            size_t tail_len = strlen(src);

            if (tail_len > remaining)
            {
                fprintf(stderr, "ERROR: Substitution would exceed the maximum line length.\n");
                goto finish;
            }
            memcpy(dst, src, tail_len);
            dst += tail_len;
        }
        *dst = '\0';

        if (strcmp(buf, lines[i]) == 0)
        {
            continue;
        }

        copy = strdup(buf);
        if (!copy)
        {
            perror("strdup");
            goto finish;
        }
        OPENSSL_cleanse(lines[i], strlen(lines[i]));
        free(lines[i]);
        lines[i] = copy;
        modified = 1;
    }

finish:
    if (modified)
    {
        return buffer_changed(path);
    }
    return 0;
}

static void help_command(void)
{
    printf("Available commands:\n");
    printf("  p           - print buffer\n");
    printf("  a           - append lines at end\n");
    printf("  i           - insert lines before line number\n");
    printf("  c           - change (replace) line number\n");
    printf("  d           - delete line number\n");
    printf("  =           - print number of lines\n");
    printf("  /pattern/   - search for pattern\n");
    printf("  s/old/new/  - substitute old => new (global)\n");
    printf("  w           - write (encrypt and save)\n");
    printf("  q           - quit editor (unsaved changes remain recoverable)\n");
    printf("  h           - show this help\n");
}

int main(int argc, char *argv[])
{
    char cmd[256];
    char *pattern;
    char confirm_password[MAX_PASSWORD_LEN];
    struct stat st;
    FILE *file = NULL;
    int backup_recovery_loaded;
    int recovery_status;
    int backup_status;
    int save_status;
    struct rlimit rl = {0};

    memset(password, 0, sizeof(password));
    memset(confirm_password, 0, sizeof(confirm_password));
    memset(current_committed_hash, 0, sizeof(current_committed_hash));
    current_buffer_dirty = 0;
    current_loaded_from_backup = 0;
    current_recovery_valid = 1;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s <file>\n", argv[0]);
        return 1;
    }

    if (!install_signal_handlers())
    {
        return 1;
    }

    umask(0077);
    unsetenv("HISTFILE");
    unsetenv("HISTSIZE");
    unsetenv("HISTFILESIZE");
    setrlimit(RLIMIT_CORE, &rl);

    if (!load_default_provider())
    {
        fprintf(stderr, "ERROR: Could not load OpenSSL default provider.\n");
        return 1;
    }
    if (!lock_process_memory())
    {
        return 1;
    }

    if (!secure_get_password("Password: ", password, sizeof(password)))
    {
        secure_cleanup();
        return 1;
    }
    if (!open_editor_file(argv[1], &file, &st))
    {
        secure_cleanup();
        return 1;
    }
    if (flock(fileno(file), LOCK_EX | LOCK_NB) == -1)
    {
        fprintf(stderr, "ERROR: File is already open in another instance.\n");
        secure_cleanup();
        fclose(file);
        return 1;
    }
    update_open_file_identity(&st);
    if (!compute_sha256_file(file, current_committed_hash))
    {
        secure_cleanup();
        fclose(file);
        return 1;
    }

    if (st.st_size == 0)
    {
        if (!secure_get_password("Confirm Password: ", confirm_password, sizeof(confirm_password)))
        {
            secure_cleanup();
            fclose(file);
            return 1;
        }
        if (strcmp(password, confirm_password) != 0)
        {
            fprintf(stderr, "Passwords do not match.\n");
            secure_cleanup();
            OPENSSL_cleanse(confirm_password, sizeof(confirm_password));
            fclose(file);
            return 1;
        }
        OPENSSL_cleanse(confirm_password, sizeof(confirm_password));

        recovery_status = load_recovery_snapshot(argv[1], current_committed_hash);
        if (recovery_status < 0)
        {
            secure_cleanup();
            fclose(file);
            return 1;
        }
        if (recovery_status == 1)
        {
            current_buffer_dirty = 1;
            current_recovery_valid = 1;
            printf("Recovered unsaved changes from the encrypted recovery snapshot.\n");
        }
        else
        {
            backup_status = recover_from_backup_chain(argv[1], &backup_recovery_loaded);
            if (backup_status < 0)
            {
                secure_cleanup();
                fclose(file);
                return 1;
            }
            if (backup_status == 1)
            {
                if (backup_recovery_loaded)
                {
                    printf("WARNING: Primary file was empty or missing; recovered from backup and recovery snapshot.\n");
                }
                else
                {
                    printf("WARNING: Primary file was empty or missing; recovered from backup copy.\n");
                }
            }
        }
    }
    else
    {
        recovery_status = load_recovery_snapshot(argv[1], current_committed_hash);
        if (recovery_status < 0)
        {
            secure_cleanup();
            fclose(file);
            return 1;
        }
        if (recovery_status == 1)
        {
            current_buffer_dirty = 1;
            current_recovery_valid = 1;
            printf("Recovered unsaved changes from the encrypted recovery snapshot.\n");
        }
        else if (!load_encrypted(file))
        {
            backup_status = recover_from_backup_chain(argv[1], &backup_recovery_loaded);
            if (backup_status <= 0)
            {
                secure_cleanup();
                fclose(file);
                return 1;
            }

            if (backup_recovery_loaded)
            {
                printf("WARNING: Primary file could not be opened; recovered from backup and recovery snapshot.\n");
            }
            else
            {
                printf("WARNING: Primary file could not be opened; recovered from backup copy.\n");
            }
        }
    }

    while (1)
    {
        if (terminate_signal != 0)
        {
            printf("\n");
            break;
        }

        printf("> ");
        fflush(stdout);
        if (!fgets(cmd, sizeof(cmd), stdin))
        {
            if (terminate_signal != 0 || errno == EINTR)
            {
                printf("\n");
            }
            break;
        }
        if (strchr(cmd, '\n') == NULL)
        {
            discard_rest_of_line();
            fprintf(stderr, "ERROR: Command exceeds the supported limit.\n");
            continue;
        }

        switch (cmd[0])
        {
        case 'p':
            print_buffer();
            break;
        case 'a':
            (void)append_lines(argv[1]);
            break;
        case 'i':
            (void)insert_lines(argv[1]);
            break;
        case 'c':
            (void)change_line(argv[1]);
            break;
        case 'd':
            (void)delete_line(argv[1]);
            break;
        case '=':
            printf("Lines: %zu\n", line_count);
            break;
        case 'w':
            save_status = save_encrypted_atomic(argv[1], &file);
            if (save_status == SAVE_OK)
            {
                printf("File written.\n");
            }
            else if (save_status == SAVE_REOPEN_FAILED)
            {
                secure_cleanup();
                return 1;
            }
            break;
        case 'q':
            if (!ensure_recoverable_state_for_exit(argv[1]))
            {
                break;
            }
            if (current_buffer_dirty)
            {
                printf("Unsaved changes remain recoverable in the encrypted recovery data.\n");
            }
            else
            {
                (void)remove_sidecar_if_exists(argv[1], ".recovery");
            }
            secure_cleanup();
            fclose(file);
            return 0;
        case '/':
            pattern = strtok(cmd + 1, "/\n");
            if (pattern)
            {
                search_pattern(pattern);
            }
            break;
        case 's':
            if (cmd[1] == '/')
            {
                const char *old = strtok(cmd + 2, "/");
                const char *new = strtok(NULL, "/\n");

                if (old && new)
                {
                    (void)substitute(argv[1], old, new);
                }
            }
            else
            {
                printf("Invalid substitute command format. Use 's/old/new'.\n");
            }
            break;
        case 'h':
            help_command();
            break;
        default:
            printf("Unknown command.\n");
            break;
        }
    }

    if (!ensure_recoverable_state_for_exit(argv[1]))
    {
        secure_cleanup();
        if (file)
        {
            fclose(file);
        }
        return 1;
    }

    secure_cleanup();
    if (current_buffer_dirty)
    {
        printf("Unsaved changes remain recoverable in the encrypted recovery data.\n");
    }
    if (file)
    {
        fclose(file);
    }
    return 0;
}
