#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <openssl/provider.h>
#include <openssl/rand.h>

extern char password[1024];
int load_encrypted(FILE *f);
void secure_cleanup(void);

static int init_fuzz_environment(void)
{
    static int initialized = 0;

    if (!initialized)
    {
        int null_fd = open("/dev/null", O_WRONLY);

        if (null_fd != -1)
        {
            (void)dup2(null_fd, STDERR_FILENO);
            close(null_fd);
        }
        if (OSSL_PROVIDER_load(NULL, "default") == NULL)
        {
            return 0;
        }
        initialized = 1;
    }

    return 1;
}

static void run_one(const uint8_t *data, size_t size)
{
    FILE *f = NULL;

    f = tmpfile();
    if (!f)
    {
        return;
    }
    if (size != 0 && fwrite(data, 1, size, f) != size)
    {
        fclose(f);
        return;
    }
    rewind(f);

    memset(password, 0, 1024);
    memcpy(password, "fuzz-password", sizeof("fuzz-password") - 1);
    (void)load_encrypted(f);
    secure_cleanup();
    memset(password, 0, 1024);

    fclose(f);
}

#ifdef EED_LIBFUZZER
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (!init_fuzz_environment())
    {
        return 0;
    }
    run_one(data, size);
    return 0;
}
#else
int main(int argc, char **argv)
{
    static const size_t edge_sizes[] = {
        0, 1, 2, 15, 16, 31, 32, 40, 63, 64, 65, 96, 127, 128, 255, 256, 511, 512, 1023, 1024, 2048, 4096};
    size_t runs = 1000;
    unsigned char size_bytes[4];
    unsigned char *buf = NULL;
    size_t max_size = 4096;

    if (argc == 3 && strcmp(argv[1], "--runs") == 0)
    {
        char *end = NULL;
        unsigned long long parsed = strtoull(argv[2], &end, 10);

        if (!end || *end != '\0' || parsed == 0)
        {
            fprintf(stderr, "usage: %s [--runs N]\n", argv[0]);
            return 1;
        }
        runs = (size_t)parsed;
    }
    else if (argc != 1)
    {
        fprintf(stderr, "usage: %s [--runs N]\n", argv[0]);
        return 1;
    }

    if (!init_fuzz_environment())
    {
        return 1;
    }

    buf = malloc(max_size);
    if (!buf)
    {
        perror("malloc");
        return 1;
    }

    for (size_t i = 0; i < runs; i++)
    {
        size_t size;

        if (i < sizeof(edge_sizes) / sizeof(edge_sizes[0]))
        {
            size = edge_sizes[i];
        }
        else
        {
            if (RAND_bytes(size_bytes, sizeof(size_bytes)) != 1)
            {
                fprintf(stderr, "RAND_bytes failed.\n");
                free(buf);
                return 1;
            }
            size = ((size_t)size_bytes[0] << 24 |
                    (size_t)size_bytes[1] << 16 |
                    (size_t)size_bytes[2] << 8 |
                    (size_t)size_bytes[3]) % (max_size + 1);
        }

        if (size != 0 && RAND_bytes(buf, (int)size) != 1)
        {
            fprintf(stderr, "RAND_bytes failed.\n");
            free(buf);
            return 1;
        }

        run_one(buf, size);
    }

    OPENSSL_cleanse(buf, max_size);
    free(buf);
    printf("fuzz-load-encrypted-ok %zu\n", runs);
    return 0;
}
#endif
