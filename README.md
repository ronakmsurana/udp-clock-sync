# udp-clock-sync
A distributed network clock synchronization system over UDP.

Compile instructions for mac:
gcc server.c -o dtls_server -I$(brew --prefix openssl)/include -L$(brew --prefix openssl)/lib -lssl -lcrypto
gcc client.c -o dtls_client -I$(brew --prefix openssl)/include -L$(brew --prefix openssl)/lib -lssl -lcrypto

To generate certifactes:
openssl req -x509 -newkey rsa:2048 -nodes -keyout server-key.pem -out server-cert.pem -days 365