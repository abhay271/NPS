#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
typedef SOCKET socket_t;
#define CLOSESOCKET closesocket
#define POPEN _popen
#define PCLOSE _pclose
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
typedef int socket_t;
#define CLOSESOCKET close
#define POPEN popen
#define PCLOSE pclose
#endif

#define MAGIC 0xDEADBEEF
#define VERSION 0x01
#define MSG_DH_KEY 0x00
#define MSG_RSA_PUBKEY 0x01
#define MSG_IMAGE_CHUNK 0x02
#define MSG_HASH_FILE 0x03
#define MSG_ACK 0x04
#define CHUNK_SIZE 4096

static int ensure_winsock(void) {
#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "[sender] WSAStartup failed\n");
        return -1;
    }
#endif
    return 0;
}

static void cleanup_winsock(void) {
#ifdef _WIN32
    WSACleanup();
#endif
}

static int send_all(socket_t sock, const uint8_t *buf, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        int n = send(sock, (const char *)(buf + sent), (int)(len - sent), 0);
        if (n <= 0) {
            return -1;
        }
        sent += (size_t)n;
    }
    return 0;
}

static int recv_all(socket_t sock, uint8_t *buf, size_t len) {
    size_t got = 0;
    while (got < len) {
        int n = recv(sock, (char *)(buf + got), (int)(len - got), 0);
        if (n <= 0) {
            return -1;
        }
        got += (size_t)n;
    }
    return 0;
}

static uint8_t header_checksum(const uint8_t *header18) {
    uint8_t c = 0;
    for (int i = 0; i < 18; i++) {
        c ^= header18[i];
    }
    return c;
}

static void build_header(
    uint8_t out[19],
    uint8_t msg_type,
    uint32_t chunk_id,
    uint32_t total_chunks,
    uint32_t payload_size
) {
    uint32_t magic_n = htonl(MAGIC);
    uint32_t chunk_n = htonl(chunk_id);
    uint32_t total_n = htonl(total_chunks);
    uint32_t size_n = htonl(payload_size);

    memcpy(out + 0, &magic_n, 4);
    out[4] = VERSION;
    out[5] = msg_type;
    memcpy(out + 6, &chunk_n, 4);
    memcpy(out + 10, &total_n, 4);
    memcpy(out + 14, &size_n, 4);
    out[18] = header_checksum(out);
}

static int parse_header(
    const uint8_t in[19],
    uint8_t *msg_type,
    uint32_t *chunk_id,
    uint32_t *total_chunks,
    uint32_t *payload_size
) {
    uint8_t expected = header_checksum(in);
    if (expected != in[18]) {
        return -1;
    }

    uint32_t magic_n;
    memcpy(&magic_n, in + 0, 4);
    uint32_t magic = ntohl(magic_n);
    if (magic != MAGIC || in[4] != VERSION) {
        return -1;
    }

    uint32_t tmp;
    *msg_type = in[5];

    memcpy(&tmp, in + 6, 4);
    *chunk_id = ntohl(tmp);

    memcpy(&tmp, in + 10, 4);
    *total_chunks = ntohl(tmp);

    memcpy(&tmp, in + 14, 4);
    *payload_size = ntohl(tmp);

    return 0;
}

static int send_packet(
    socket_t sock,
    uint8_t msg_type,
    uint32_t chunk_id,
    uint32_t total_chunks,
    const uint8_t *payload,
    uint32_t payload_size
) {
    uint8_t header[19];
    build_header(header, msg_type, chunk_id, total_chunks, payload_size);

    if (send_all(sock, header, sizeof(header)) != 0) {
        return -1;
    }

    if (payload_size > 0 && send_all(sock, payload, payload_size) != 0) {
        return -1;
    }

    return 0;
}

static int recv_packet(
    socket_t sock,
    uint8_t *msg_type,
    uint32_t *chunk_id,
    uint32_t *total_chunks,
    uint8_t **payload,
    uint32_t *payload_size
) {
    uint8_t header[19];
    if (recv_all(sock, header, sizeof(header)) != 0) {
        return -1;
    }

    if (parse_header(header, msg_type, chunk_id, total_chunks, payload_size) != 0) {
        return -1;
    }

    *payload = NULL;
    if (*payload_size > 0) {
        *payload = (uint8_t *)malloc(*payload_size + 1);
        if (!*payload) {
            return -1;
        }
        if (recv_all(sock, *payload, *payload_size) != 0) {
            free(*payload);
            *payload = NULL;
            return -1;
        }
        (*payload)[*payload_size] = '\0';
    }

    return 0;
}

static uint8_t *read_file(const char *path, size_t *len_out) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        return NULL;
    }

    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return NULL;
    }
    long sz = ftell(f);
    if (sz < 0) {
        fclose(f);
        return NULL;
    }
    rewind(f);

    uint8_t *buf = (uint8_t *)malloc((size_t)sz + 1);
    if (!buf) {
        fclose(f);
        return NULL;
    }

    size_t got = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    if (got != (size_t)sz) {
        free(buf);
        return NULL;
    }

    buf[sz] = '\0';
    *len_out = (size_t)sz;
    return buf;
}

static int write_file(const char *path, const uint8_t *data, size_t len) {
    FILE *f = fopen(path, "wb");
    if (!f) {
        return -1;
    }
    size_t wrote = fwrite(data, 1, len, f);
    fclose(f);
    return wrote == len ? 0 : -1;
}

static int run_prepare_and_echo(const char *message) {
    char cmd[2048];
    snprintf(cmd, sizeof(cmd), "python prepare.py --message \"%s\"", message);

    FILE *pipe = POPEN(cmd, "r");
    if (!pipe) {
        fprintf(stderr, "[sender] Failed to run prepare.py\n");
        return -1;
    }

    char line[2048];
    while (fgets(line, sizeof(line), pipe)) {
        printf("[sender][prepare] %s", line);
    }

    int rc = PCLOSE(pipe);
    if (rc != 0) {
        fprintf(stderr, "[sender] prepare.py exited with code %d\n", rc);
        return -1;
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: sender \"message here\"\n");
        return 1;
    }

    if (ensure_winsock() != 0) {
        return 1;
    }

    printf("[sender] Creating socket...\n");
    socket_t sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == (socket_t)-1) {
        fprintf(stderr, "[sender] socket() failed\n");
        cleanup_winsock();
        return 1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(8080);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    printf("[sender] Connecting to 127.0.0.1:8080...\n");
    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        fprintf(stderr, "[sender] connect() failed\n");
        CLOSESOCKET(sock);
        cleanup_winsock();
        return 1;
    }
    printf("[sender] Connected to 127.0.0.1:8080\n");

    uint8_t msg_type;
    uint32_t chunk_id, total_chunks, payload_size;
    uint8_t *payload = NULL;

    if (recv_packet(sock, &msg_type, &chunk_id, &total_chunks, &payload, &payload_size) != 0 || msg_type != MSG_DH_KEY) {
        fprintf(stderr, "[sender] Failed to receive receiver DH key\n");
        CLOSESOCKET(sock);
        cleanup_winsock();
        return 1;
    }

    if (write_file("dh_state/receiver_dh_pub.txt", payload, payload_size) != 0) {
        fprintf(stderr, "[sender] Failed to write receiver DH public value\n");
        free(payload);
        CLOSESOCKET(sock);
        cleanup_winsock();
        return 1;
    }
    free(payload);

    if (system("python dh_helper.py gen_sender") != 0) {
        fprintf(stderr, "[sender] dh_helper gen_sender failed\n");
        CLOSESOCKET(sock);
        cleanup_winsock();
        return 1;
    }

    size_t sender_pub_len = 0;
    uint8_t *sender_pub = read_file("dh_state/sender_dh_pub.txt", &sender_pub_len);
    if (!sender_pub) {
        fprintf(stderr, "[sender] Failed to read sender DH public value\n");
        CLOSESOCKET(sock);
        cleanup_winsock();
        return 1;
    }

    if (send_packet(sock, MSG_DH_KEY, 0, 1, sender_pub, (uint32_t)sender_pub_len) != 0) {
        fprintf(stderr, "[sender] Failed to send sender DH public value\n");
        free(sender_pub);
        CLOSESOCKET(sock);
        cleanup_winsock();
        return 1;
    }
    free(sender_pub);
    printf("[sender] DH exchange complete. AES key derived.\n");

    if (recv_packet(sock, &msg_type, &chunk_id, &total_chunks, &payload, &payload_size) != 0 || msg_type != MSG_RSA_PUBKEY) {
        fprintf(stderr, "[sender] Failed to receive RSA public key\n");
        CLOSESOCKET(sock);
        cleanup_winsock();
        return 1;
    }

    if (write_file("keys/public.pem", payload, payload_size) != 0) {
        fprintf(stderr, "[sender] Failed to write keys/public.pem\n");
        free(payload);
        CLOSESOCKET(sock);
        cleanup_winsock();
        return 1;
    }
    free(payload);
    printf("[sender] RSA public key received and saved\n");

    printf("[sender] Running prepare.py...\n");
    if (run_prepare_and_echo(argv[1]) != 0) {
        CLOSESOCKET(sock);
        cleanup_winsock();
        return 1;
    }

    size_t image_len = 0;
    uint8_t *image = read_file("output/stego.png", &image_len);
    if (!image) {
        fprintf(stderr, "[sender] Failed to read output/stego.png\n");
        CLOSESOCKET(sock);
        cleanup_winsock();
        return 1;
    }

    size_t hash_len = 0;
    uint8_t *hash_data = read_file("output/hash.txt", &hash_len);
    if (!hash_data) {
        fprintf(stderr, "[sender] Failed to read output/hash.txt\n");
        free(image);
        CLOSESOCKET(sock);
        cleanup_winsock();
        return 1;
    }

    uint32_t total = (uint32_t)((image_len + CHUNK_SIZE - 1) / CHUNK_SIZE);
    size_t bytes_sent = 0;
    time_t t0 = time(NULL);

    for (uint32_t i = 0; i < total; i++) {
        size_t offset = (size_t)i * CHUNK_SIZE;
        size_t remain = image_len - offset;
        uint32_t chunk = (uint32_t)(remain > CHUNK_SIZE ? CHUNK_SIZE : remain);

        if (send_packet(sock, MSG_IMAGE_CHUNK, i, total, image + offset, chunk) != 0) {
            fprintf(stderr, "[sender] Failed sending image chunk %u\n", i + 1);
            free(image);
            free(hash_data);
            CLOSESOCKET(sock);
            cleanup_winsock();
            return 1;
        }

        bytes_sent += chunk;
        printf("[sender] Chunk %u/%u (%u bytes)\n", i + 1, total, chunk);
    }

    if (send_packet(sock, MSG_HASH_FILE, 0, 1, hash_data, (uint32_t)hash_len) != 0) {
        fprintf(stderr, "[sender] Failed sending hash file\n");
        free(image);
        free(hash_data);
        CLOSESOCKET(sock);
        cleanup_winsock();
        return 1;
    }
    bytes_sent += hash_len;

    free(image);
    free(hash_data);

    if (recv_packet(sock, &msg_type, &chunk_id, &total_chunks, &payload, &payload_size) != 0 || msg_type != MSG_ACK) {
        fprintf(stderr, "[sender] Failed receiving ACK\n");
        CLOSESOCKET(sock);
        cleanup_winsock();
        return 1;
    }
    free(payload);

    time_t t1 = time(NULL);
    double elapsed = difftime(t1, t0);
    if (elapsed <= 0.0) {
        elapsed = 0.001;
    }
    double kbps = ((double)bytes_sent / 1024.0) / elapsed;

    printf("[sender] ACK received. Transfer complete.\n");
    printf("[sender] %zu bytes sent in %.2fs (%.2f KB/s)\n", bytes_sent, elapsed, kbps);

    CLOSESOCKET(sock);
    cleanup_winsock();
    return 0;
}
