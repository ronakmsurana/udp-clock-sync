#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/time.h>

#define SERVER_IP "10.30.201.234"
#define PORT 8080
#define SYNC_INTERVAL_SEC 2
#define MAX_RETRIES 3

// Protocol Structure — matches server exactly
typedef struct {
    double t0; // Client send time
    double t1; // Server receive time
    double t2; // Server transmit time
} SyncPacket;

double get_timestamp() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec + (tv.tv_usec / 1000000.0);
}

int main() {
    int sockfd;
    struct sockaddr_in server_addr;

    OpenSSL_add_ssl_algorithms();
    SSL_load_error_strings();

    SSL_CTX *ctx = SSL_CTX_new(DTLS_client_method());
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Verifying server certificates
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

    if (SSL_CTX_load_verify_locations(ctx, "server-cert.pem", NULL) != 1) {
        fprintf(stderr, "Error loading server-cert.pem. Make sure the file is in this folder!\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // FIX 2: Check socket() return value
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // Receive timeout to handle packet loss / unresponsive server
    struct timeval tv;
    tv.tv_sec  = 3;
    tv.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port   = htons(PORT);

    // Check inet_pton return value
    if (inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr) <= 0) {
        fprintf(stderr, "Invalid server IP address: %s\n", SERVER_IP);
        exit(EXIT_FAILURE);
    }

    // Check connect() return value
    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("connect");
        exit(EXIT_FAILURE);
    }

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sockfd);

    if (SSL_connect(ssl) <= 0)
    {
        fprintf(stderr, "\n❌ CONNECTION FAILED: The server did not respond.\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    printf("DTLS handshake complete. Starting sync loop (interval: %ds)...\n\n",
           SYNC_INTERVAL_SEC);

    // Track consecutive failures; exit cleanly after MAX_RETRIES
    int consecutive_failures = 0;

    while (1) {
        SyncPacket packet;
        memset(&packet, 0, sizeof(packet));

        // Record T0 right before sending
        packet.t0 = get_timestamp();

        if (SSL_write(ssl, &packet, sizeof(packet)) <= 0) {
            fprintf(stderr, "SSL_write failed. Server may have closed the connection.\n");
            break;
        }

        int bytes_read = SSL_read(ssl, &packet, sizeof(packet));

        if (bytes_read == sizeof(SyncPacket)) {
            consecutive_failures = 0;  // FIX 3: Reset on success

            double t3 = get_timestamp();

            // math for offset and delay calculation
            double delay  = (t3 - packet.t0) - (packet.t2 - packet.t1);
            double offset = ((packet.t1 - packet.t0) + (packet.t2 - t3)) / 2.0;
            double synced = get_timestamp() + offset;

            // printf("TIMESTAMPS\n");
            // printf("  T0 (Client Send):     %.8f\n", packet.t0);
            // printf("  T1 (Server Receive):  %.8f\n", packet.t1);
            // printf("  T2 (Server Transmit): %.8f\n", packet.t2);
            // printf("  T3 (Client Receive):  %.8f\n", t3);
            // printf("  Delay:  %.8f s\n", delay);
            // printf("  Offset: %+.8f s\n", offset);
            // printf("  Synchronized time:    %.8f\n\n", synced);

            // Output pure JSON for the frontend bridge
            printf("{\"delay\": %.8f, \"offset\": %.8f, \"synced_time\": %.8f}\n", delay, offset, synced);
            fflush(stdout); // Crucial: forces the data out immediately

        } else {
            // Count failures; only give up after MAX_RETRIES
            consecutive_failures++;
            int ssl_err = SSL_get_error(ssl, bytes_read);
            fprintf(stderr, "Read failed (SSL error %d). Attempt %d/%d.\n",
                    ssl_err, consecutive_failures, MAX_RETRIES);

            if (consecutive_failures >= MAX_RETRIES) {
                fprintf(stderr, "Too many consecutive failures. Exiting.\n");
                break;
            }
        }

        sleep(SYNC_INTERVAL_SEC);
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sockfd);
    SSL_CTX_free(ctx);

    return 0;
}