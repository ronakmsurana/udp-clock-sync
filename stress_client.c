#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/time.h>

#define SERVER_IP "127.0.0.1"
#define PORT 8080
#define NUM_REQUESTS 1000 // Hammer the server with 1,000 requests

typedef struct {
    double t0;
    double t1;
    double t2;
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

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    
    // Add a 2-second timeout just in case the server drops a packet under load
    struct timeval tv_timeout;
    tv_timeout.tv_sec = 2;
    tv_timeout.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv_timeout, sizeof(tv_timeout));

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr);

    connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr));

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sockfd);

    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    } 

    printf("Connected! Starting stress test (%d requests)...\n", NUM_REQUESTS);

    double test_start_time = get_timestamp();
    double total_delay = 0.0;
    int successful_requests = 0;

    // --- The High-Speed Benchmark Loop ---
    for (int i = 0; i < NUM_REQUESTS; i++) {
        SyncPacket packet;
        packet.t0 = get_timestamp();
        
        if (SSL_write(ssl, &packet, sizeof(packet)) <= 0) break;

        if (SSL_read(ssl, &packet, sizeof(packet)) == sizeof(SyncPacket)) {
            double t3 = get_timestamp();
            double delay = (t3 - packet.t0) - (packet.t2 - packet.t1);
            total_delay += delay;
            successful_requests++;
        } else {
            printf("Request %d dropped!\n", i);
        }
    }

    double test_end_time = get_timestamp();
    double test_duration = test_end_time - test_start_time;

    // --- The Metrics Output ---
    printf("\n=== PERFORMANCE METRICS ===\n");
    printf("Total Requests:     %d\n", NUM_REQUESTS);
    printf("Successful:         %d\n", successful_requests);
    printf("Total Time:         %.4f seconds\n", test_duration);
    
    if (successful_requests > 0) {
        printf("Average Latency:    %.6f seconds\n", total_delay / successful_requests);
        printf("Server Throughput:  %.0f Requests/Second\n", successful_requests / test_duration);
    }
    printf("===========================\n");

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sockfd);
    SSL_CTX_free(ctx);

    return 0;
}