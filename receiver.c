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

static int ensure_winsock(void) {
#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "[receiver] WSAStartup failed\n");
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

static int run_extract_and_echo(void) {
    FILE *pipe = POPEN("python extract.py", "r");
    if (!pipe) {
        return -1;
    }

    char line[2048];
    while (fgets(line, sizeof(line), pipe)) {
        printf("[receiver][extract] %s", line);
    }

    int rc = PCLOSE(pipe);
    return rc == 0 ? 0 : -1;
}

int main(void) {
    if (ensure_winsock() != 0) {
        return 1;
    }

    printf("[receiver] Creating socket...\n");
    socket_t server = socket(AF_INET, SOCK_STREAM, 0);
    if (server == (socket_t)-1) {
        fprintf(stderr, "[receiver] socket() failed\n");
        cleanup_winsock();
        return 1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(8080);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    printf("[receiver] Binding on port 8080...\n");
    if (bind(server, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        fprintf(stderr, "[receiver] bind() failed\n");
        CLOSESOCKET(server);
        cleanup_winsock();
        return 1;
    }

    printf("[receiver] Listening on port 8080...\n");
    if (listen(server, 1) != 0) {
        fprintf(stderr, "[receiver] listen() failed\n");
        CLOSESOCKET(server);
        cleanup_winsock();
        return 1;
    }

    struct sockaddr_in client_addr;
#ifdef _WIN32
    int client_len = sizeof(client_addr);
#else
    socklen_t client_len = sizeof(client_addr);
#endif
    socket_t client = accept(server, (struct sockaddr *)&client_addr, &client_len);
    if (client == (socket_t)-1) {
        fprintf(stderr, "[receiver] accept() failed\n");
        CLOSESOCKET(server);
        cleanup_winsock();
        return 1;
    }

    printf("[receiver] Connection accepted from %s\n", inet_ntoa(client_addr.sin_addr));

    if (system("python dh_helper.py gen_receiver") != 0) {
        fprintf(stderr, "[receiver] dh_helper gen_receiver failed\n");
        CLOSESOCKET(client);
        CLOSESOCKET(server);
        cleanup_winsock();
        return 1;
    }

    size_t recv_pub_len = 0;
    uint8_t *recv_pub = read_file("dh_state/receiver_dh_pub.txt", &recv_pub_len);
    if (!recv_pub) {
        fprintf(stderr, "[receiver] Failed to read receiver DH public value\n");
        CLOSESOCKET(client);
        CLOSESOCKET(server);
        cleanup_winsock();
        return 1;
    }

    if (send_packet(client, MSG_DH_KEY, 0, 1, recv_pub, (uint32_t)recv_pub_len) != 0) {
        fprintf(stderr, "[receiver] Failed to send receiver DH public value\n");
        free(recv_pub);
        CLOSESOCKET(client);
        CLOSESOCKET(server);
        cleanup_winsock();
        return 1;
    }
    free(recv_pub);

    uint8_t msg_type;
    uint32_t chunk_id, total_chunks, payload_size;
    uint8_t *payload = NULL;

    if (recv_packet(client, &msg_type, &chunk_id, &total_chunks, &payload, &payload_size) != 0 || msg_type != MSG_DH_KEY) {
        fprintf(stderr, "[receiver] Failed to receive sender DH key\n");
        CLOSESOCKET(client);
        CLOSESOCKET(server);
        cleanup_winsock();
        return 1;
    }

    if (write_file("dh_state/sender_dh_pub.txt", payload, payload_size) != 0) {
        fprintf(stderr, "[receiver] Failed to write sender DH key\n");
        free(payload);
        CLOSESOCKET(client);
        CLOSESOCKET(server);
        cleanup_winsock();
        return 1;
    }
    free(payload);

    if (system("python dh_helper.py compute_receiver") != 0) {
        fprintf(stderr, "[receiver] dh_helper compute_receiver failed\n");
        CLOSESOCKET(client);
        CLOSESOCKET(server);
        cleanup_winsock();
        return 1;
    }

    if (system("python dh_helper.py gen_rsa") != 0) {
        fprintf(stderr, "[receiver] dh_helper gen_rsa failed\n");
        CLOSESOCKET(client);
        CLOSESOCKET(server);
        cleanup_winsock();
        return 1;
    }

    size_t pubkey_len = 0;
    uint8_t *pubkey = read_file("keys/public.pem", &pubkey_len);
    if (!pubkey) {
        fprintf(stderr, "[receiver] Failed to read keys/public.pem\n");
        CLOSESOCKET(client);
        CLOSESOCKET(server);
        cleanup_winsock();
        return 1;
    }

    if (send_packet(client, MSG_RSA_PUBKEY, 0, 1, pubkey, (uint32_t)pubkey_len) != 0) {
        fprintf(stderr, "[receiver] Failed to send RSA public key\n");
        free(pubkey);
        CLOSESOCKET(client);
        CLOSESOCKET(server);
        cleanup_winsock();
        return 1;
    }
    free(pubkey);
    printf("[receiver] DH exchange complete\n");
    printf("[receiver] RSA keypair generated, public key sent\n");

    uint8_t *image_buf = NULL;
    size_t image_size = 0;
    time_t t0 = time(NULL);

    while (1) {
        if (recv_packet(client, &msg_type, &chunk_id, &total_chunks, &payload, &payload_size) != 0) {
            fprintf(stderr, "[receiver] Failed receiving packet\n");
            free(image_buf);
            CLOSESOCKET(client);
            CLOSESOCKET(server);
            cleanup_winsock();
            return 1;
        }

        if (msg_type != MSG_IMAGE_CHUNK) {
            break;
        }

        uint8_t *next = (uint8_t *)realloc(image_buf, image_size + payload_size);
        if (!next) {
            fprintf(stderr, "[receiver] Out of memory while receiving image\n");
            free(payload);
            free(image_buf);
            CLOSESOCKET(client);
            CLOSESOCKET(server);
            cleanup_winsock();
            return 1;
        }

        image_buf = next;
        memcpy(image_buf + image_size, payload, payload_size);
        image_size += payload_size;

        printf("[receiver] Chunk %u/%u received (%u bytes)\n", chunk_id + 1, total_chunks, payload_size);

        free(payload);
        payload = NULL;

        if (chunk_id + 1 == total_chunks) {
            if (recv_packet(client, &msg_type, &chunk_id, &total_chunks, &payload, &payload_size) != 0) {
                fprintf(stderr, "[receiver] Failed receiving hash packet\n");
                free(image_buf);
                CLOSESOCKET(client);
                CLOSESOCKET(server);
                cleanup_winsock();
                return 1;
            }
            break;
        }
    }

    if (msg_type != MSG_HASH_FILE) {
        fprintf(stderr, "[receiver] Expected hash packet\n");
        free(payload);
        free(image_buf);
        CLOSESOCKET(client);
        CLOSESOCKET(server);
        cleanup_winsock();
        return 1;
    }

    if (write_file("received/stego.png", image_buf, image_size) != 0) {
        fprintf(stderr, "[receiver] Failed writing received/stego.png\n");
        free(payload);
        free(image_buf);
        CLOSESOCKET(client);
        CLOSESOCKET(server);
        cleanup_winsock();
        return 1;
    }

    if (write_file("received/hash.txt", payload, payload_size) != 0) {
        fprintf(stderr, "[receiver] Failed writing received/hash.txt\n");
        free(payload);
        free(image_buf);
        CLOSESOCKET(client);
        CLOSESOCKET(server);
        cleanup_winsock();
        return 1;
    }

    free(payload);
    free(image_buf);

    const char ack[] = "OK";
    if (send_packet(client, MSG_ACK, 0, 1, (const uint8_t *)ack, (uint32_t)strlen(ack)) != 0) {
        fprintf(stderr, "[receiver] Failed sending ACK\n");
        CLOSESOCKET(client);
        CLOSESOCKET(server);
        cleanup_winsock();
        return 1;
    }

    time_t t1 = time(NULL);
    double elapsed = difftime(t1, t0);
    if (elapsed <= 0.0) {
        elapsed = 0.001;
    }
    size_t total_bytes = image_size + payload_size;
    double kbps = ((double)total_bytes / 1024.0) / elapsed;

    printf("[receiver] Transfer complete - %zu bytes in %.2fs (%.2f KB/s)\n", total_bytes, elapsed, kbps);

    if (run_extract_and_echo() != 0) {
        fprintf(stderr, "[receiver] extract.py failed\n");
    }

    CLOSESOCKET(client);
    CLOSESOCKET(server);
    cleanup_winsock();
    return 0;
}
