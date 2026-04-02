#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>          // FIX 1: needed for SIGCHLD
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/wait.h>        // FIX 1: needed for waitpid / SIG_IGN
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <sys/time.h>

#define PORT 8080

// Protocol Structure
typedef struct {
    double t0; // Client send time
    double t1; // Server receive time
    double t2; // Server transmit time
} SyncPacket;

// Helper to get time in seconds with microsecond precision
double get_timestamp() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec + (tv.tv_usec / 1000000.0);
}

// Generate a static cookie for DTLS handshake, HMAC-based (e.g. HMAC-SHA256 over client IP+port+secret)

// Global secret key for cookies (generated once per server run)
unsigned char cookie_secret[16];
int cookie_initialized = 0;

int generate_cookie(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len) {
    // 1. Generate a random 16-byte secret key on the first run
    if (!cookie_initialized) {
        if (!RAND_bytes(cookie_secret, 16)) return 0;
        cookie_initialized = 1;
    }

    // 2. Extract the connecting client's IP address and Port
    struct sockaddr_in peer;
    BIO_dgram_get_peer(SSL_get_rbio(ssl), &peer);

    // 3. Cryptographically hash the Secret Key + Client IP together
    unsigned int result_len;
    HMAC(EVP_sha256(), 
         cookie_secret, 16, 
         (const unsigned char *)&peer.sin_addr, sizeof(peer.sin_addr), 
         cookie, &result_len);

    *cookie_len = result_len;
    // printf("Generated Cookie (Hex): ");
    // for (unsigned int i = 0; i < result_len; i++) {
    //     printf("%02x", cookie[i]);
    // }
    // printf("\n");
    // fflush(stdout);
    return 1;
}

int verify_cookie(SSL *ssl, const unsigned char *cookie, unsigned int cookie_len) {
    unsigned char expected_cookie[EVP_MAX_MD_SIZE];
    unsigned int expected_len;

    // Run the same math to see what the cookie *should* be for this IP
    generate_cookie(ssl, expected_cookie, &expected_len);

    // 4. Compare what the client sent with our cryptographic expectation
    // Using CRYPTO_memcmp prevents "timing attacks" where hackers guess passwords based on processing speed
    if (cookie_len == expected_len && CRYPTO_memcmp(cookie, expected_cookie, expected_len) == 0) {
        return 1; 
    }
    return 0; // Fake or spoofed cookie!
}

void handle_client(SSL *ssl, int client_fd, int client_id) {

    // Complete the DTLS handshake
    if (SSL_accept(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    printf("Secure DTLS session established. Handling client %d...\n", client_id);

    // -- The Deadman's Switch (Read Timeout)
    struct timeval tv;
    tv.tv_sec = 10; // 10 seconds of silence = client is dead
    tv.tv_usec = 0;
    setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    SyncPacket packet;
    while (1) {
        int len = SSL_read(ssl, &packet, sizeof(packet));

        if (len <= 0) {
            int err = SSL_get_error(ssl, len);
            // FIX 2: Distinguish clean disconnect from real errors
            if (err == SSL_ERROR_ZERO_RETURN) {
                printf("Client %d closed the session cleanly.\n", client_id);
            } else {
                printf("Client %d disconnected (SSL error %d). Child shutting down.\n", client_id,err);
            }
            break;
        }

        if (len == sizeof(SyncPacket) || len == 16)
        {
            // Record T1 immediately upon receiving
            packet.t1 = get_timestamp();
            // printf("Sync request received. T0=%.6f\n", packet.t0);

            // Record T2 immediately before sending back
            packet.t2 = get_timestamp();

            if (SSL_write(ssl, &packet, sizeof(packet)) <= 0) {
                fprintf(stderr, "SSL_write failed. Dropping client.\n");
                break;
            }
            // printf("Replied with T1=%.6f T2=%.6f\n", packet.t1, packet.t2);
            double client_synced_time;
            int bytes_read = SSL_read(ssl, &client_synced_time, sizeof(client_synced_time));
            
            if (bytes_read == sizeof(client_synced_time)) {
                double server_current_time = packet.t1;
                double difference = client_synced_time - server_current_time;
                
                printf("[Client %d] Sync Report: Client %.9f, Server %.9f, diff %.9f\n", client_id, client_synced_time, server_current_time, difference);
            }
        }
        else
        {
            fprintf(stderr, "Unexpected packet size %d (expected %zu). Ignoring.\n",
                    len, sizeof(SyncPacket));
        }
    }

cleanup:
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(client_fd);
    exit(0);
}

int main() {
    // FIX 1: Prevent zombie child processes — kernel reaps them automatically
    signal(SIGCHLD, SIG_IGN);

    int listen_fd;
    struct sockaddr_in server_addr, client_addr;

    OpenSSL_add_ssl_algorithms();
    SSL_load_error_strings();
    SSL_CTX *ctx = SSL_CTX_new(DTLS_server_method());
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Load server certificate and private key
    if (SSL_CTX_use_certificate_file(ctx, "server-cert.pem", SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, "server-key.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // FIX 4: Verify that the private key matches the certificate
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Private key does not match certificate.\n");
        exit(EXIT_FAILURE);
    }

    SSL_CTX_set_cookie_generate_cb(ctx, generate_cookie);
    SSL_CTX_set_cookie_verify_cb(ctx, verify_cookie);

    // FIX 2: Check socket() return value
    listen_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (listen_fd < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    int opt = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family      = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port        = htons(PORT);

    // FIX 2: Check bind() return value
    if (bind(listen_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind");
        exit(EXIT_FAILURE);
    }

    printf("DTLS Time Server listening on UDP port %d\n", PORT);

    int client_id = 0;
    while (1) {
        SSL *ssl = SSL_new(ctx);
        BIO *bio = BIO_new_dgram(listen_fd, BIO_NOCLOSE);
        SSL_set_bio(ssl, bio, bio);
        SSL_set_options(ssl, SSL_OP_COOKIE_EXCHANGE);


        // Block until a valid ClientHello with correct cookie arrives
        while (DTLSv1_listen(ssl, (BIO_ADDR *)&client_addr) <= 0);
        client_id++;
        printf("Client %d verified. Forking child process...\n", client_id);

        // Create a new connected socket dedicated to this client
        int connected_fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (connected_fd < 0) {
            perror("socket (child)");
            SSL_free(ssl);
            continue;  // FIX 2: Don't crash the whole server on one bad socket
        }
        setsockopt(connected_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        setsockopt(connected_fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));

        if (bind(connected_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
            perror("bind (child)");
            close(connected_fd);
            SSL_free(ssl);
            continue;  // FIX 2: Recover gracefully instead of exit(EXIT_FAILURE)
        }

        connect(connected_fd, (struct sockaddr*)&client_addr, sizeof(client_addr));

        pid_t pid = fork();
        if (pid == 0) {
            // Child: take over the connected socket
            close(listen_fd);
            BIO_set_fd(SSL_get_rbio(ssl), connected_fd, BIO_NOCLOSE);
            BIO_ctrl(SSL_get_rbio(ssl), BIO_CTRL_DGRAM_SET_CONNECTED, 0, &client_addr);
            handle_client(ssl, connected_fd, client_id);
            // handle_client calls exit(0) — never reaches here
        } else if (pid > 0) {
            // Parent: clean up its copy and loop back for the next client
            SSL_free(ssl);
            close(connected_fd);
        } else {
            perror("fork");
            SSL_free(ssl);
            close(connected_fd);
        }
    }

    close(listen_fd);
    SSL_CTX_free(ctx);
    return 0;
}