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

// -- Protocol Structure
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

    // -- Synchronization Process
    SyncPacket packet;
    
    // Record T0 right before hitting the network
    packet.t0 = get_timestamp();
    SSL_write(ssl, &packet, sizeof(packet));

    // Wait for the server's reply
    int bytes_read = SSL_read(ssl, &packet, sizeof(packet));
    
    if (bytes_read == sizeof(SyncPacket)) {
        // Record T3 immediately upon receiving the packet back
        double t3 = get_timestamp();

        // -- math
        // Network Delay (d)
        double delay = (packet.t1 - packet.t0) + (t3 - packet.t2);
        
        // Clock Offset (theta)
        double offset = ((packet.t1 - packet.t0) + (packet.t2 - t3)) / 2.0;

        printf("\n--- Synchronization Complete ---\n");
        printf("T0 (Client Send):      %.8f\n", packet.t0);
        printf("T1 (Server Receive):   %.8f\n", packet.t1);
        printf("T2 (Server Transmit):  %.8f\n", packet.t2);
        printf("T3 (Client Receive):   %.8f\n", t3);
        printf("--------------------------------\n");
        printf("Network Delay (d):     %.8f seconds\n", delay);
        printf("Clock Offset (theta):  %.8f seconds\n", offset);
        
        // Calculate the perfectly synchronized time
        double synchronized_time = get_timestamp() + offset;
        printf("\nApplying offset to client clock...\n");
        printf("Synchronized Time:     %.8f\n", synchronized_time);

    } else {
        printf("Failed to read complete sync packet from server.\n");
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sockfd);
    SSL_CTX_free(ctx);

    return 0;
}