# udp-clock-sync
# Secure UDP Distributed Clock Synchronization

A concurrent client-server system written in C that synchronizes system clocks over UDP. It uses a 4-timestamp request-reply protocol to calculate precise network delay and clock drift, completely secured by OpenSSL (DTLS).

## Prerequisites
* **macOS / Linux:** Requires GCC and OpenSSL.
  * Mac: `brew install openssl`
  * Ubuntu/Debian: `sudo apt install build-essential libssl-dev`
* **Windows:** Must be run using Windows Subsystem for Linux (WSL). Install WSL using `wsl --install`

Open PowerShell, run 
```
wsl
```
use the Ubuntu commands above.

## Quick Start

### 1. Generate the Security Certificate
The server requires a self-signed certificate to run the DTLS handshake.
Run this in your project folder:
```
openssl req -x509 -newkey rsa:4096 -keyout server-key.pem -out server-cert.pem -days 365 -nodes
```
(Hit Enter to skip through the requested details)

### 2. Compile the Code
*(Mac Users: Ensure you have added the Homebrew OpenSSL paths to your `~/.zshrc` profile first).*
```
gcc server.c -o dtls_server -lssl -lcrypto
gcc client.c -o dtls_client -lssl -lcrypto
gcc stress_client.c -o stress_client -lssl -lcrypto
```
Incase the above commands fail due to OpenSSL errors, use these instead:

```
gcc server.c -o dtls_server -I$(brew --prefix openssl)/include -L$(brew --prefix openssl)/lib -lssl -lcrypto
gcc client.c -o dtls_client -I$(brew --prefix openssl)/include -L$(brew --prefix openssl)/lib -lssl -lcrypto
gcc stress_client.c -o stress_client -I$(brew --prefix openssl)/include -L$(brew --prefix openssl)/lib -lssl -lcrypto
```

## Usage

### Standard Synchronization
1. **Start the Server:**
   `./dtls_server`

2. **Start the Client** (Open a new terminal/device):
   `./dtls_client `

   *The client will connect, calculate the network delay/offset, and ping the server every 5 seconds to correct clock drift.*

### Concurrent Stress Test
To evaluate the server's performance under heavy load:
1. Ensure the server is running.

2. Run the benchmarking script:
   `./run_test.sh`
   
   *This spawns 10 concurrent clients that will hit the server with 10,000 requests and output the average latency and throughput.*

## Architecture & Design Choices

* **Transport Layer (UDP):** Built natively using POSIX `<sys/socket.h>`. UDP was chosen to minimize transport overhead, which is critical for microsecond-level timekeeping.
* **Security Layer (OpenSSL DTLS):** Because standard TLS requires the guaranteed delivery of TCP, it shatters over UDP. This system utilizes `DTLS_server_method()` and enforces a cryptographic "Cookie Exchange" during the handshake to completely mitigate UDP IP-spoofing and DoS attacks.
* **Concurrency Engine (`fork` & `SO_REUSEPORT`):** The server handles simultaneous clients without blocking. Once a client passes the DTLS cookie challenge, the server uses `fork()` to spawn an isolated child process. By utilizing `SO_REUSEPORT`, the OS kernel routes that specific client's encrypted datagrams directly to the child, leaving the parent instantly ready for new connections.
* **Resilience & Edge Cases:** Memory Leaks: Child processes utilize a "Deadman's Switch" (`SO_RCVTIMEO`) to safely self-terminate if a client abruptly disconnects.
    * Zombie Processes: The parent server automatically reaps child processes via `SIGCHLD`.
    * Garbage Data: Invalid packets that do not match the strict 24-byte `SyncPacket` struct are instantly rejected.

## The Synchronization Math
The protocol exchanges a `SyncPacket` containing timestamps recorded with `gettimeofday()` (microsecond precision).
* T0: Client Send Time
* T1: Server Receive Time
* T2: Server Transmit Time
* T3: Client Receive Time

Once the client receives the packet back, it calculates:
* **Network Delay (d):** (T3 - T0) - (T2 - T1)
* **Clock Offset (theta):** (T1 - T0) + (T2 - T3)/2