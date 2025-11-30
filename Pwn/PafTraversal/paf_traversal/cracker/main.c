#include <stdio.h>
#include <string.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

static const char *FIFO_IN  = "/tmp/cracker.in";
static const char *FIFO_OUT = "/tmp/cracker.out";
static volatile sig_atomic_t stop_flag = 0;

static void compute_md5(const unsigned char *data, size_t data_len, unsigned char* out) {
    MD5(data, data_len, out);
}
static void compute_sha1(const unsigned char *data, size_t data_len, unsigned char* out) {
    SHA1(data, data_len, out);
}
static void compute_sha256(const unsigned char *data, size_t data_len, unsigned char* out) {
    SHA256(data, data_len, out);
}
static void compute_sha512(const unsigned char *data, size_t data_len, unsigned char* out) {
    SHA512(data, data_len, out);
}

typedef void (*compute_fn)(const unsigned char *data, size_t data_len, unsigned char* out);

static void cleanup_fifos(void) {
    unlink(FIFO_IN);
    unlink(FIFO_OUT);
}

static void signal_handler(int signum) {
    (void)signum;
    stop_flag = 1;
    cleanup_fifos();
    exit(0);
}

static void to_hex(const unsigned char *data, size_t length, char *out) {
    for (size_t i = 0; i < length; ++i) {
        sprintf(out + (i * 2), "%02x", data[i]);
    }
    out[length * 2] = '\0';
}

static void from_hex(const char *hex_str, unsigned char *out, size_t out_len) {
    for (size_t i = 0; i < out_len; ++i) {
        sscanf(hex_str + (i * 2), "%2hhx", &out[i]);
    }
}

void handle_request(const char *algo_type_str, const char *hash_str, const char *wordlist_str) {
    unsigned char output_bin[SHA512_DIGEST_LENGTH];
    char hash_bin[SHA512_DIGEST_LENGTH];
    char output_hex[SHA512_DIGEST_LENGTH * 2 + 1];

    int outfd = open(FIFO_OUT, O_WRONLY);
	if (outfd < 0) {
        perror("open FIFO_OUT for writing in handle_request");
        return;
    }

    int algo_type = atoi(algo_type_str);
    printf("[%d] target hash: %s  (wordlist: %s)\n", algo_type, hash_str, wordlist_str);
    fflush(stdout);

    int output_len = SHA256_DIGEST_LENGTH;
    switch (algo_type) {
        case 0: output_len = MD5_DIGEST_LENGTH; break;
        case 1: output_len = SHA_DIGEST_LENGTH; break;
        case 2: output_len = SHA256_DIGEST_LENGTH; break;
        default:
            fprintf(stderr, "Unsupported algorithm type: %d\n", algo_type);
            dprintf(outfd, "ERROR:unsupported algorithm type %d\n", algo_type);
            close(outfd);
    }

    compute_fn hash_functions[] = {
        compute_md5,
        compute_sha1,
        compute_sha256,
    };
    compute_fn* hash_fn = &hash_functions[algo_type];

    FILE *wordlist = fopen(wordlist_str, "r");
    if (!wordlist) {
        perror("fopen wordlist");
        dprintf(outfd, "ERROR:could not open wordlist '%s': %s\n", wordlist_str, strerror(errno));
        close(outfd);
        return;
    }

    from_hex(hash_str, (unsigned char *)hash_bin, output_len);

    char pw[512];
    int found = 0;
    while (fgets(pw, sizeof(pw), wordlist)) {
        size_t pwlen = strcspn(pw, "\r\n");
        pw[pwlen] = '\0';
        if (pwlen == 0) continue;

        (*hash_fn)((const unsigned char *)pw, pwlen, output_bin);
        to_hex(output_bin, output_len, output_hex);

        printf("Trying: '%s' -> %s (target %s)\n", pw, output_hex, hash_str);
        fflush(stdout);

        if (memcmp(output_bin, hash_bin, output_len) == 0) {
            dprintf(outfd, "SUCCESS:%s\n", pw);
            printf("SUCCESS: hash(%s) == %s\n", pw, hash_str);
            found = 1;
            break;
        }
    }

    if (!found) {
        dprintf(outfd, "ERROR:password not found\n");
        printf("ERROR:Password not found for %s\n", hash_str);
    }

    close(outfd);
    fclose(wordlist);
}

int main(void) {
    atexit(cleanup_fifos);
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    cleanup_fifos();

    if (mkfifo(FIFO_IN, 0666) < 0) {
        if (errno != EEXIST) {
            perror("mkfifo FIFO_IN");
            return 1;
        }
    }
    if (mkfifo(FIFO_OUT, 0666) < 0) {
        if (errno != EEXIST) {
            perror("mkfifo FIFO_OUT");
            unlink(FIFO_IN);
            return 1;
        }
    }

    chmod(FIFO_IN, 0666);
    chmod(FIFO_OUT, 0666);

    printf("Hash server listening on FIFOs:\n  IN:  %s\n  OUT: %s\n", FIFO_IN, FIFO_OUT);
    printf("Protocol: write a request (three lines) to %s and read the single-line response from %s\n", FIFO_IN, FIFO_OUT);
    printf("Request format (text lines):\n  <algo_type>\n  <hash_hex>\n  <wordlist_path>\n");
    printf("Notes: Clients should open %s for reading before (or concurrently with) writing the request\n", FIFO_OUT);
    fflush(stdout);

    const size_t BUF_SZ = 16 * 1024;
    char *buf = malloc(BUF_SZ);
    if (!buf) {
        perror("malloc");
        cleanup_fifos();
        return 1;
    }

    while (!stop_flag) {
        int infd = open(FIFO_IN, O_RDONLY);
        if (infd < 0) {
            if (stop_flag) break;
            perror("open FIFO_IN for read");
            sleep(1);
            continue;
        }

        ssize_t total = 0;
        while (total < (ssize_t)(BUF_SZ - 1)) {
            ssize_t r = read(infd, buf + total, BUF_SZ - 1 - total);
            if (r < 0) {
                if (errno == EINTR) continue;
                perror("read FIFO_IN");
                break;
            } else if (r == 0) {
                break;
            }
            total += r;
        }
        close(infd);

        if (total <= 0) {
            continue;
        }
        buf[total] = '\0';

        char *lines[4] = {0};
        size_t linec = 0;
        char *p = buf;
        while (*p && linec < 4) {
            // skip leading CR/LF
            while (*p == '\r' || *p == '\n') p++;
            if (*p == '\0') break;
            lines[linec++] = p;
            char *nl = strpbrk(p, "\r\n");
            if (!nl) break;
            *nl = '\0';
            p = nl + 1;
        }

        if (linec < 3) {
            fprintf(stderr, "Invalid request: expected 3 lines, got %zu\n", linec);

            int outfd = open(FIFO_OUT, O_WRONLY | O_NONBLOCK);
            if (outfd >= 0) {
                dprintf(outfd, "ERROR:invalid request: expected 3 lines, got %zu\n", linec);
                close(outfd);
            }
            continue;
        }

        const char *algo_type_str = lines[0];
        const char *hash_str = lines[1];
        const char *wordlist_str = lines[2];

        pid_t pid = fork();
        if (pid < 0) {
            perror("fork");

            int outfd = open(FIFO_OUT, O_WRONLY | O_NONBLOCK);
            if (outfd >= 0) {
                dprintf(outfd, "ERROR:server fork failed\n");
                close(outfd);
            }
            continue;
        } else if (pid == 0) {
            signal(SIGINT, SIG_DFL);
            signal(SIGTERM, SIG_DFL);
            handle_request(algo_type_str, hash_str, wordlist_str);
            _exit(0);
        }
    }

    free(buf);
    cleanup_fifos();
    return 0;
}