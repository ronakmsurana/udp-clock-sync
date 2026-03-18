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
#include <time.h>

#define PORT 8080
#define BUFFER_SIZE 1024

// Secret used for generating cookies to verify client IPs
unsigned char cookie_secret[16];
int cookie_initialized = 0;

// Callback: Generates a cookie for the client based on their IP/Port
int generate_cookie(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len) {
    struct sockaddr_in peer;
    (void)BIO_dgram_get_peer(SSL_get_rbio(ssl), &peer);
    
    // In a production environment, use HMAC with the cookie_secret.
    // For this basic implementation, we use a simple static copy.
    memcpy(cookie, "dtls_cookie_123", 15);
    *cookie_len = 15;
    return 1;
}

// Callback: Verifies the cookie sent back by the client
int verify_cookie(SSL *ssl, const unsigned char *cookie, unsigned int cookie_len) {
    if (cookie_len == 15 && memcmp(cookie, "dtls_cookie_123", 15) == 0) {
        return 1;
    }
    return 0;
}

void handle_client(SSL *ssl, int client_fd) {
    char buf[BUFFER_SIZE];
    
    // Complete the SSL handshake
    if (SSL_accept(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    printf("Secure connection established with client.\n");

    // Read the time request
    int len = SSL_read(ssl, buf, sizeof(buf) - 1);
    if (len > 0) {
        buf[len] = '\0';
        printf("Client Request: %s\n", buf);

        // Generate the offset/delay payload (Currently just sending server time)
        time_t current_time = time(NULL);
        char response[BUFFER_SIZE];
        snprintf(response, sizeof(response), "SERVER_TIME:%ld", current_time);

        // Send the encrypted reply
        SSL_write(ssl, response, strlen(response));
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

    // 1. Initialize OpenSSL
    OpenSSL_add_ssl_algorithms();
    SSL_load_error_strings();
    SSL_CTX *ctx = SSL_CTX_new(DTLS_server_method());

    // 2. Load Certificates (Mandatory for SSL/TLS requirement)
    if (SSL_CTX_use_certificate_file(ctx, "server-cert.pem", SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, "server-key.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Set cookie callbacks for DTLSv1_listen
    SSL_CTX_set_cookie_generate_cb(ctx, generate_cookie);
    SSL_CTX_set_cookie_verify_cb(ctx, verify_cookie);

    // 3. Create and bind the initial UDP socket
    listen_fd = socket(AF_INET, SOCK_DGRAM, 0);
    int opt = 1;
    
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    bind(listen_fd, (struct sockaddr*)&server_addr, sizeof(server_addr));
    printf("DTLS Server listening on UDP port %d\n", PORT);

    // 4. The listening loop
    while (1) {
        SSL *ssl = SSL_new(ctx);
        BIO *bio = BIO_new_dgram(listen_fd, BIO_NOCLOSE);
        SSL_set_bio(ssl, bio, bio);
        SSL_set_options(ssl, SSL_OP_COOKIE_EXCHANGE);

        // Listen for incoming ClientHello and process the cookie exchange
        while (DTLSv1_listen(ssl, (BIO_ADDR *)&client_addr) <= 0);

        printf("Client verified. Forking new process...\n");

        // 5. Concurrency: Hand off the client to a new connected socket
        int connected_fd = socket(AF_INET, SOCK_DGRAM, 0);
        int opt = 1;
        setsockopt(connected_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        setsockopt(connected_fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
        if (bind(connected_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
            perror("CRITICAL: Child socket bind failed");
            exit(EXIT_FAILURE);
        }
        connect(connected_fd, (struct sockaddr*)&client_addr, sizeof(client_addr));

        if (fork() == 0) {
            // Child Process
            close(listen_fd); // Child doesn't need the listening socket
            
            // Re-bind the SSL object to the new connected socket
            BIO_set_fd(SSL_get_rbio(ssl), connected_fd, BIO_NOCLOSE);
            BIO_ctrl(SSL_get_rbio(ssl), BIO_CTRL_DGRAM_SET_CONNECTED, 0, &client_addr);
            
            handle_client(ssl, connected_fd);
        } else {
            // Parent Process
            SSL_free(ssl); // Parent cleans up this specific SSL state
        }
    }

    close(listen_fd);
    SSL_CTX_free(ctx);
    return 0;
}