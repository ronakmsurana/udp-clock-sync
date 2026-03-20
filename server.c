#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
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
// generate cookies
int generate_cookie(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len) {
    memcpy(cookie, "dtls_cookie_123", 15);
    *cookie_len = 15;
    return 1;
}

// Verifies the cookie sent back by the client
int verify_cookie(SSL *ssl, const unsigned char *cookie, unsigned int cookie_len) {
    if (cookie_len == 15 && memcmp(cookie, "dtls_cookie_123", 15) == 0) return 1;
    return 0;
}

void handle_client(SSL *ssl, int client_fd) {
    
    // Complete the SSL handshake
    if (SSL_accept(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    SyncPacket packet;
    
    // Read the incoming packet
    int len = SSL_read(ssl, &packet, sizeof(packet));
    if (len == sizeof(SyncPacket)) {
        // Record T1 immediately upon receiving
        packet.t1 = get_timestamp();
        
        printf("Received sync request from client. T0 recorded as: %f\n", packet.t0);

        // Record T2 immediately before sending back
        packet.t2 = get_timestamp();
        
        // Send the populated packet back
        SSL_write(ssl, &packet, sizeof(packet));
        printf("Replied to client with T1 and T2.\n");
    }

cleanup:
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(client_fd);
    exit(0); // Exit the child process
}

int main() {
    int listen_fd;
    struct sockaddr_in server_addr, client_addr;

    // Initialize OpenSSL
    OpenSSL_add_ssl_algorithms();
    SSL_load_error_strings();
    SSL_CTX *ctx = SSL_CTX_new(DTLS_server_method());

    // Load Certificates (Mandatory for SSL/TLS requirement)
    if (SSL_CTX_use_certificate_file(ctx, "server-cert.pem", SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, "server-key.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Set cookie callbacks for DTLSv1_listen
    SSL_CTX_set_cookie_generate_cb(ctx, generate_cookie);
    SSL_CTX_set_cookie_verify_cb(ctx, verify_cookie);

    // Create and bind the initial UDP socket
    listen_fd = socket(AF_INET, SOCK_DGRAM, 0);

    int opt = 1;
    
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    bind(listen_fd, (struct sockaddr*)&server_addr, sizeof(server_addr));
    printf("DTLS Time Server listening on UDP port %d\n", PORT);

    // The listening loop
    while (1) {
        SSL *ssl = SSL_new(ctx);
        BIO *bio = BIO_new_dgram(listen_fd, BIO_NOCLOSE);
        SSL_set_bio(ssl, bio, bio);
        SSL_set_options(ssl, SSL_OP_COOKIE_EXCHANGE);

        // Listen for incoming ClientHello and process the cookie exchange
        while (DTLSv1_listen(ssl, (BIO_ADDR *)&client_addr) <= 0);

        printf("Client verified. Forking new process...\n");

        // Concurrency: Hand off the client to a new connected socket
        int connected_fd = socket(AF_INET, SOCK_DGRAM, 0);
        setsockopt(connected_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        setsockopt(connected_fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
        
        if (bind(connected_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
            perror("CRITICAL: Child socket bind failed");
            exit(EXIT_FAILURE);
        }

        connect(connected_fd, (struct sockaddr*)&client_addr, sizeof(client_addr));

        if (fork() == 0) {
            close(listen_fd);
            BIO_set_fd(SSL_get_rbio(ssl), connected_fd, BIO_NOCLOSE);
            BIO_ctrl(SSL_get_rbio(ssl), BIO_CTRL_DGRAM_SET_CONNECTED, 0, &client_addr);
            handle_client(ssl, connected_fd);
        } else {
            SSL_free(ssl);
        }
    }

    close(listen_fd);
    SSL_CTX_free(ctx);
    return 0;
}