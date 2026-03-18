#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define SERVER_IP "127.0.0.1"
#define PORT 8080
#define BUFFER_SIZE 1024

int main() {
    int sockfd;
    struct sockaddr_in server_addr;

    // 1. Initialize OpenSSL for the Client
    OpenSSL_add_ssl_algorithms();
    SSL_load_error_strings();
    
    // Use the explicit DTLS client method
    SSL_CTX *ctx = SSL_CTX_new(DTLS_client_method());
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // 2. Create the UDP Socket
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr);

    // 3. "Connect" the UDP socket
    // In UDP, connect() doesn't establish a session, but it binds the 
    // default destination address to the socket for the OS and OpenSSL.
    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connect failed");
        exit(EXIT_FAILURE);
    }

    // 4. Bind the Socket to the SSL Object
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sockfd);

    printf("Initiating DTLS handshake with %s:%d...\n", SERVER_IP, PORT);

    // 5. Perform the DTLS Handshake
    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
    } else {
        printf("Secure connection established!\n");

        // 6. Send the Time Request Payload
        const char *request = "TIME_REQ";
        printf("Sending request: %s\n", request);
        SSL_write(ssl, request, strlen(request));

        // 7. Wait for and Read the Encrypted Server Reply
        char buffer[BUFFER_SIZE];
        int bytes_read = SSL_read(ssl, buffer, sizeof(buffer) - 1);
        
        if (bytes_read > 0) {
            buffer[bytes_read] = '\0';
            printf("Received encrypted reply: %s\n", buffer);
        } else {
            printf("Failed to read server response.\n");
        }
    }

    // 8. Cleanup
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sockfd);
    SSL_CTX_free(ctx);

    return 0;
}