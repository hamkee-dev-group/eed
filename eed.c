#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <regex.h>
#include <errno.h>
#include <sys/stat.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <openssl/provider.h>

#define MAX_LINES 16384
#define MAX_LINE_LEN 1024
#define SALT_LEN 16
#define IV_LEN 16
#define KEY_LEN 32
#define MAC_KEY_LEN 32
#define HMAC_LEN 32
#define PBKDF2_ITERATIONS 100000

char *lines[MAX_LINES];
size_t line_count = 0;
char password[128];

int load_default_provider(void)
{
    OSSL_PROVIDER *provider = OSSL_PROVIDER_load(NULL, "default");
    return (!provider) ? 0 : 1;
}

void secure_get_password(char *buf, size_t buflen)
{
    struct termios old, new;

    printf("Password: ");
    fflush(stdout);
    if (tcgetattr(STDIN_FILENO, &old) == -1)
    {
        perror("tcgetattr");
        exit(1);
    }

    new = old;
    new.c_lflag &= ~(ECHO);
    if (tcsetattr(STDIN_FILENO, TCSANOW, &new) == -1)
    {
        perror("tcsetattr");
        exit(1);
    }

    if (!fgets(buf, buflen, stdin))
    {
        fprintf(stderr, "Error reading password.\n");
        exit(1);
    }

    if (tcsetattr(STDIN_FILENO, TCSANOW, &old) == -1)
    {
        perror("tcsetattr");
        exit(1);
    }

    printf("\n");
    buf[strcspn(buf, "\n")] = '\0';
}

void free_lines(void)
{
    for (size_t i = 0; i < line_count; i++)
    {
        if (lines[i])
        {
            OPENSSL_cleanse(lines[i], strlen(lines[i]));
            free(lines[i]);
        }
    }
    line_count = 0;
}
int load_encrypted(const char *filename)
{
    unsigned char salt[SALT_LEN], iv[IV_LEN], key[KEY_LEN], mac_key[MAC_KEY_LEN];
    unsigned char *ciphertext;
    unsigned char file_hmac[HMAC_LEN];
    unsigned char calc_hmac[HMAC_LEN];

    EVP_MAC *mac;
    EVP_MAC_CTX *ctx;
    EVP_CIPHER_CTX *cipher_ctx;
    OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string("digest", "SHA256", 0),
        OSSL_PARAM_END};

    size_t ciphertext_len;
    size_t hmac_len = 0;
    unsigned char outbuf[1024 + EVP_MAX_BLOCK_LENGTH];
    int outlen;

    char *line = NULL;
    size_t linelen = 0;
    int chunk_offset = 0;
    int chunk_size;
    size_t fsize;
    long ftellsize;
    FILE *f;
    bzero(calc_hmac, HMAC_LEN);
    bzero(file_hmac, HMAC_LEN);
    f = fopen(filename, "rb");
    if (!f)
    {
        perror("fopen");
        return 0;
    }

    if (fseek(f, 0, SEEK_END) == -1)
    {
        perror("fseek");
        fclose(f);
        return 0;
    }
    ftellsize = ftell(f);
    if (ftellsize == -1)
    {
        perror("ftell");
        fclose(f);
        return 0;
    }
    fsize = (size_t)ftellsize;
    if (fseek(f, 0L, SEEK_SET) == -1)
    {
        perror("fseek");
        fclose(f);
        return 0;
    }
    if (fread(salt, 1, SALT_LEN, f) != SALT_LEN)
    {
        perror("fread SALT");
        fclose(f);
        return 0;
    }
    if (fread(iv, 1, IV_LEN, f) != IV_LEN)
    {
        perror("fread IV");
        fclose(f);
        return 0;
    }

    PKCS5_PBKDF2_HMAC(password, strlen(password), salt, SALT_LEN,
                      PBKDF2_ITERATIONS, EVP_sha256(), KEY_LEN, key);
    PKCS5_PBKDF2_HMAC(password, strlen(password), salt, SALT_LEN,
                      PBKDF2_ITERATIONS, EVP_sha256(), MAC_KEY_LEN, mac_key);

    ciphertext_len = fsize - SALT_LEN - IV_LEN - HMAC_LEN;
    ciphertext = malloc(ciphertext_len);
    if (ciphertext == NULL)
    {
        perror("malloc");
        fclose(f);
        return 0;
    }
    if (fread(ciphertext, 1, ciphertext_len, f) != ciphertext_len)
    {
        perror("fread ciphertext");
        free(ciphertext);
        fclose(f);
        return 0;
    }

    if (fread(file_hmac, 1, HMAC_LEN, f) != HMAC_LEN)
    {
        perror("fread HMAC");
        free(ciphertext);
        fclose(f);
        return 0;
    }
    fclose(f);

    mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    if (!mac)
    {
        fprintf(stderr, "ERROR: EVP_MAC_fetch failed.\n");
        free(ciphertext);
        return 0;
    }
    ctx = EVP_MAC_CTX_new(mac);
    if (!ctx)
    {
        fprintf(stderr, "ERROR: EVP_MAC_CTX_new failed.\n");
        EVP_MAC_free(mac);
        free(ciphertext);
        return 0;
    }
    if (!EVP_MAC_init(ctx, mac_key, MAC_KEY_LEN, params))
    {
        fprintf(stderr, "ERROR: EVP_MAC_init failed.\n");
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
        free(ciphertext);
        return 0;
    }

    if (!EVP_MAC_update(ctx, iv, IV_LEN) ||
        !EVP_MAC_update(ctx, ciphertext, ciphertext_len) ||
        !EVP_MAC_final(ctx, calc_hmac, &hmac_len, HMAC_LEN))
    {
        fprintf(stderr, "ERROR: EVP_MAC operation failed.\n");
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
        free(ciphertext);
        return 0;
    }
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
    if (CRYPTO_memcmp(calc_hmac, file_hmac, HMAC_LEN) != 0)
    {
        fprintf(stderr, "ERROR: File integrity check failed (MAC mismatch).\n");
        OPENSSL_cleanse(key, KEY_LEN);
        OPENSSL_cleanse(mac_key, MAC_KEY_LEN);
        free(ciphertext);
        return 0;
    }

    cipher_ctx = EVP_CIPHER_CTX_new();
    if (!cipher_ctx)
    {
        fprintf(stderr, "ERROR: EVP_CIPHER_CTX_new failed.\n");
        OPENSSL_cleanse(key, KEY_LEN);
        OPENSSL_cleanse(mac_key, MAC_KEY_LEN);
        free(ciphertext);
        return 0;
    }
    if (!EVP_DecryptInit_ex(cipher_ctx, EVP_aes_256_cbc(), NULL, key, iv))
    {
        fprintf(stderr, "ERROR: EVP_DecryptInit_ex failed.\n");
        EVP_CIPHER_CTX_free(cipher_ctx);
        OPENSSL_cleanse(key, KEY_LEN);
        OPENSSL_cleanse(mac_key, MAC_KEY_LEN);
        free(ciphertext);
        return 0;
    }
    while (chunk_offset < (int)ciphertext_len)
    {
        chunk_size = (ciphertext_len - chunk_offset > 1024) ? 1024 : (ciphertext_len - chunk_offset);
        if (!EVP_DecryptUpdate(cipher_ctx, outbuf, &outlen, ciphertext + chunk_offset, chunk_size))
        {
            fprintf(stderr, "ERROR: EVP_DecryptUpdate failed.\n");
            EVP_CIPHER_CTX_free(cipher_ctx);
            OPENSSL_cleanse(key, KEY_LEN);
            OPENSSL_cleanse(mac_key, MAC_KEY_LEN);
            free(ciphertext);
            return 0;
        }
        chunk_offset += chunk_size;

        for (int i = 0; i < outlen; i++)
        {
            if (linelen == 0)
            {
                line = malloc(MAX_LINE_LEN);
                if (!line)
                {
                    fprintf(stderr, "ERROR: malloc failed.\n");
                    EVP_CIPHER_CTX_free(cipher_ctx);
                    OPENSSL_cleanse(key, KEY_LEN);
                    OPENSSL_cleanse(mac_key, MAC_KEY_LEN);
                    free(ciphertext);
                    return 0;
                }
            }
            if (outbuf[i] == '\n')
            {
                line[linelen] = '\0';
                lines[line_count++] = line;
                linelen = 0;
            }
            else
            {
                if (linelen < MAX_LINE_LEN - 1)
                    line[linelen++] = outbuf[i];
            }
        }
    }

    if (EVP_DecryptFinal_ex(cipher_ctx, outbuf, &outlen))
    {
        for (int i = 0; i < outlen; i++)
        {
            if (linelen == 0)
            {
                line = malloc(MAX_LINE_LEN);
                if (!line)
                {
                    fprintf(stderr, "ERROR: malloc failed.\n");
                    EVP_CIPHER_CTX_free(cipher_ctx);
                    OPENSSL_cleanse(key, KEY_LEN);
                    OPENSSL_cleanse(mac_key, MAC_KEY_LEN);
                    free(ciphertext);
                    return 0;
                }
            }
            if (outbuf[i] == '\n')
            {
                line[linelen] = '\0';
                lines[line_count++] = line;
                linelen = 0;
            }
            else
            {
                if (linelen < MAX_LINE_LEN - 1)
                    line[linelen++] = outbuf[i];
            }
        }
    }

    EVP_CIPHER_CTX_free(cipher_ctx);
    OPENSSL_cleanse(key, KEY_LEN);
    OPENSSL_cleanse(mac_key, MAC_KEY_LEN);
    free(ciphertext);
    return 1;
}
void write_encrypted(const char *filename)
{
    unsigned char salt[SALT_LEN], iv[IV_LEN], key[KEY_LEN], mac_key[MAC_KEY_LEN];
    EVP_CIPHER_CTX *cipher_ctx;
    EVP_MAC *mac;
    EVP_MAC_CTX *ctx;
    unsigned char final_hmac[HMAC_LEN];
    size_t hmac_len = 0;
    size_t len = 0;
    unsigned char inbuf[MAX_LINE_LEN], outbuf[MAX_LINE_LEN + EVP_MAX_BLOCK_LENGTH];

    OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string("digest", "SHA256", 0),
        OSSL_PARAM_END};
    int outlen;

    FILE *f = fopen(filename, "wb");
    if (!f)
    {
        perror("fopen");
        return;
    }

    if (RAND_bytes(salt, SALT_LEN) != 1 || RAND_bytes(iv, IV_LEN) != 1)
    {
        fprintf(stderr, "ERROR: RAND_bytes failed.\n");
        fclose(f);
        return;
    }

    PKCS5_PBKDF2_HMAC(password, strlen(password), salt, SALT_LEN,
                      PBKDF2_ITERATIONS, EVP_sha256(), KEY_LEN, key);
    PKCS5_PBKDF2_HMAC(password, strlen(password), salt, SALT_LEN,
                      PBKDF2_ITERATIONS, EVP_sha256(), MAC_KEY_LEN, mac_key);

    if (fwrite(salt, 1, SALT_LEN, f) != SALT_LEN)
    {
        perror("fwrite SALT");
        fclose(f);
        return;
    }
    if (fwrite(iv, 1, IV_LEN, f) != IV_LEN)
    {
        perror("fwrite IV");
        fclose(f);
        return;
    }

    cipher_ctx = EVP_CIPHER_CTX_new();
    if (!cipher_ctx)
    {
        fprintf(stderr, "ERROR: EVP_CIPHER_CTX_new failed.\n");
        fclose(f);
        return;
    }
    if (!EVP_EncryptInit_ex(cipher_ctx, EVP_aes_256_cbc(), NULL, key, iv))
    {
        fprintf(stderr, "ERROR: EVP_EncryptInit_ex failed.\n");
        EVP_CIPHER_CTX_free(cipher_ctx);
        fclose(f);
        return;
    }

    mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    if (!mac)
    {
        fprintf(stderr, "ERROR: EVP_MAC_fetch failed.\n");
        EVP_CIPHER_CTX_free(cipher_ctx);
        fclose(f);
        return;
    }
    ctx = EVP_MAC_CTX_new(mac);
    if (!ctx)
    {
        fprintf(stderr, "ERROR: EVP_MAC_CTX_new failed.\n");
        EVP_MAC_free(mac);
        EVP_CIPHER_CTX_free(cipher_ctx);
        fclose(f);
        return;
    }

    if (!EVP_MAC_init(ctx, mac_key, MAC_KEY_LEN, params))
    {
        fprintf(stderr, "ERROR: EVP_MAC_init failed.\n");
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
        EVP_CIPHER_CTX_free(cipher_ctx);
        fclose(f);
        return;
    }
    if (!EVP_MAC_update(ctx, iv, IV_LEN))
    {
        fprintf(stderr, "ERROR: EVP_MAC_update failed.\n");
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
        EVP_CIPHER_CTX_free(cipher_ctx);
        fclose(f);
        return;
    }
    for (size_t i = 0; i < line_count; i++)
    {
        len = strlen(lines[i]);
        memcpy(inbuf, lines[i], len);
        inbuf[len++] = '\n';
        if (!EVP_EncryptUpdate(cipher_ctx, outbuf, &outlen, inbuf, len))
        {
            fprintf(stderr, "ERROR: EVP_EncryptUpdate failed.\n");
            EVP_MAC_CTX_free(ctx);
            EVP_MAC_free(mac);
            EVP_CIPHER_CTX_free(cipher_ctx);
            fclose(f);
            return;
        }
        if (fwrite(outbuf, 1, outlen, f) != (size_t)outlen)
        {
            fprintf(stderr, "ERROR: fwrite failed.\n");
            EVP_MAC_CTX_free(ctx);
            EVP_MAC_free(mac);
            EVP_CIPHER_CTX_free(cipher_ctx);
            fclose(f);
            return;
        }
        if (!EVP_MAC_update(ctx, outbuf, outlen))
        {
            fprintf(stderr, "ERROR: EVP_MAC_update failed.\n");
            EVP_MAC_CTX_free(ctx);
            EVP_MAC_free(mac);
            EVP_CIPHER_CTX_free(cipher_ctx);
            fclose(f);
            return;
        }
    }
    if (!EVP_EncryptFinal_ex(cipher_ctx, outbuf, &outlen))
    {
        fprintf(stderr, "ERROR: EVP_EncryptFinal_ex failed.\n");
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
        EVP_CIPHER_CTX_free(cipher_ctx);
        fclose(f);
        return;
    }
    if (fwrite(outbuf, 1, outlen, f) != (size_t)outlen)
    {
        fprintf(stderr, "ERROR: fwrite final failed.\n");
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
        EVP_CIPHER_CTX_free(cipher_ctx);
        fclose(f);
        return;
    }
    if (!EVP_MAC_update(ctx, outbuf, outlen))
    {
        fprintf(stderr, "ERROR: EVP_MAC_update final failed.\n");
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
        EVP_CIPHER_CTX_free(cipher_ctx);
        fclose(f);
        return;
    }
    if (!EVP_MAC_final(ctx, final_hmac, &hmac_len, HMAC_LEN))
    {
        fprintf(stderr, "ERROR: EVP_MAC_final failed.\n");
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
        EVP_CIPHER_CTX_free(cipher_ctx);
        fclose(f);
        return;
    }
    if (fwrite(final_hmac, 1, HMAC_LEN, f) != HMAC_LEN)
    {
        fprintf(stderr, "ERROR: fwrite HMAC failed.\n");
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
        EVP_CIPHER_CTX_free(cipher_ctx);
        fclose(f);
        return;
    }
    EVP_CIPHER_CTX_free(cipher_ctx);
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
    OPENSSL_cleanse(key, KEY_LEN);
    OPENSSL_cleanse(mac_key, MAC_KEY_LEN);
    fclose(f);
}
void print_buffer(void)
{
    for (size_t i = 0; i < line_count; i++)
    {
        printf("%zu: %s\n", i + 1, lines[i]);
    }
}

void append_lines(void)
{
    char buf[MAX_LINE_LEN];

    printf("Enter lines, single '.' on line to finish:\n");
    while (fgets(buf, sizeof(buf), stdin))
    {
        if (strcmp(buf, ".\n") == 0)
            break;
        buf[strcspn(buf, "\n")] = '\0';
        if (line_count < MAX_LINES)
        {
            lines[line_count] = strdup(buf);
            line_count++;
        }
    }
}

void insert_lines(void)
{
    size_t n;
    char buf[MAX_LINE_LEN];
    size_t insert_pos = 0;
    printf("Insert before line number: ");
    scanf("%zu", &n);
    getchar();
    if (n < 1 || n > line_count + 1)
    {
        printf("Invalid line number\n");
        return;
    }
    printf("Enter lines, single '.' on line to finish:\n");
    insert_pos = n - 1;
    while (fgets(buf, sizeof(buf), stdin))
    {
        if (strcmp(buf, ".\n") == 0)
            break;
        buf[strcspn(buf, "\n")] = '\0';
        if (line_count < MAX_LINES)
        {
            for (size_t i = line_count; i > insert_pos; i--)
            {
                lines[i] = lines[i - 1];
            }
            lines[insert_pos++] = strdup(buf);
            line_count++;
        }
    }
}

void change_line(void)
{
    char buf[MAX_LINE_LEN];
    size_t n;
    printf("Change line number: ");
    scanf("%zu", &n);
    getchar();
    if (n == 0 || n > line_count)
    {
        printf("Invalid line number\n");
        return;
    }
    printf("New line: ");
    fgets(buf, sizeof(buf), stdin);
    buf[strcspn(buf, "\n")] = '\0';
    OPENSSL_cleanse(lines[n - 1], strlen(lines[n - 1]));
    free(lines[n - 1]);
    lines[n - 1] = strdup(buf);
}

void delete_line(void)
{
    size_t n;
    printf("Delete line number: ");
    scanf("%zu", &n);
    getchar();
    if (n == 0 || n > line_count)
    {
        printf("Invalid line number\n");
        return;
    }
    OPENSSL_cleanse(lines[n - 1], strlen(lines[n - 1]));
    free(lines[n - 1]);
    for (size_t i = n - 1; i < line_count - 1; i++)
    {
        lines[i] = lines[i + 1];
    }
    line_count--;
}

void search_pattern(const char *pattern)
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

void substitute(const char *old, const char *new)
{
    char buf[MAX_LINE_LEN];
    size_t prefix_len;
    char *pos;
    for (size_t i = 0; i < line_count; i++)
    {
        while ((pos = strstr(lines[i], old)))
        {
            memset(buf, '\0', sizeof(buf));
            prefix_len = pos - lines[i];
            snprintf(buf, sizeof(buf), "%.*s%s%s", (int)prefix_len, lines[i], new, pos + strlen(old));
            free(lines[i]);
            lines[i] = strdup(buf);
        }
    }
}

void help_command(void)
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
    printf("  q           - quit editor\n");
    printf("  h           - show this help\n");
}

void secure_cleanup(void)
{
    OPENSSL_cleanse(password, sizeof(password));
    free_lines();
}

int main(int argc, char *argv[])
{
    char cmd[256];
    char *pattern;
    char confirm_password[128];
    struct stat st;

    memset(password, 0, sizeof(password));
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s <file>\n", argv[0]);
        return 1;
    }
    if (!load_default_provider())
    {
        fprintf(stderr, "ERROR: Could not load OpenSSL default provider.\n");
        return 1;
    }
    secure_get_password(password, sizeof(password));

    if (stat(argv[1], &st) == -1)
    {
        if (errno == ENOENT)
        {
            printf("Confirm ");
            secure_get_password(confirm_password, sizeof(confirm_password));
            if (strcmp(password, confirm_password) != 0)
            {
                fprintf(stderr, "Passwords do not match.\n");
                secure_cleanup();
                OPENSSL_cleanse(confirm_password, sizeof(confirm_password));
                return 1;
            }
            OPENSSL_cleanse(confirm_password, sizeof(confirm_password));
        }
        else
        {
            perror("stat");
            secure_cleanup();
            return 1;
        }
    }
    else
    {
        if (!load_encrypted(argv[1]))
        {
            secure_cleanup();
            return 1;
        }
    }
    while (1)
    {
        printf("> ");
        if (!fgets(cmd, sizeof(cmd), stdin))
            break;
        switch (cmd[0])
        {
        case 'p':
            print_buffer();
            break;
        case 'a':
            append_lines();
            break;
        case 'i':
            insert_lines();
            break;
        case 'c':
            change_line();
            break;
        case 'd':
            delete_line();
            break;
        case '=':
            printf("Lines: %zu\n", line_count);
            break;
        case 'w':
            write_encrypted(argv[1]);
            printf("File written.\n");
            break;
        case 'q':
            secure_cleanup();
            return 0;
            break;
        case '/':
            pattern = strtok(cmd + 1, "/\n");
            if (pattern)
                search_pattern(pattern);
            break;
        case 's':
            if (cmd[1] == '/')
            {

                char *old = strtok(cmd + 2, "/");
                char *new = strtok(NULL, "/\n");
                if (old && new)
                    substitute(old, new);
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

    secure_cleanup();

    return 0;
}
