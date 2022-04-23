#include "../include/lib.h"

const char IS_UDP = '0';
const char IS_TCP = '1';
const char SEARCH = '2';
const char NEED_BIND = 1;
const char NOT_NEED_BIND = 2;
const char GET_FILE[10] = "get_file";
const char SEND_FILE[10] = "send_file";
const char TIME_OUT[10] = "time_out";
const char EXIT[10] = "exit";
const char READY_TO_ACCEPT[20] = "ready_to_accept";
const uint16_t broadcast_port = 29949;
const int secret_size = 100;
const unsigned g = 5; //constants for deffi-hellman algoritm
const unsigned p = 23;
const unsigned connection_time = 100000; //~30 min we wait between messages before shutdowning connection with client


int Socket_config(struct sockaddr_in* server, uint16_t port, int socket_type, int setsockopt_option, char is_bind_need, in_addr_t addr) {
    int a = 1;
    server -> sin_family = AF_INET;
    server -> sin_port   = htons(port);
    server -> sin_addr.s_addr = addr;
    int created_socket = socket(AF_INET, socket_type, 0);

    if (created_socket < 0) {
        log_perror("socket");
        exit(EXIT_FAILURE);
    }

    if (setsockopt_option > 0)
        if (setsockopt(created_socket, SOL_SOCKET, setsockopt_option, &a, sizeof(a)) < 0) {
            log_perror("setsockopt");
            exit(EXIT_FAILURE);
        }

    if (is_bind_need == NEED_BIND) 
        if (bind(created_socket, (struct sockaddr*) server, sizeof(*server)) < 0) {
            if (socket_type == SOCK_DGRAM && errno == 98) {
                log_perror("bind port problem\n");
                return -1;
            }
            log_perror("bind port = %hu\n", port);
            exit(EXIT_FAILURE);
        }

    return created_socket;
}


void* Mycalloc (int size_of_elem, int size)
    {
    char* mem = (char*) calloc (size, size_of_elem);
    if (mem == NULL)  {
        log_perror("Calloc error\n");
        exit (EXIT_FAILURE);
        }
    return mem;
    }


int Accept_file(char* input, int client_fd, int size, int is_udp, struct sockaddr_in* server, int key) {
    log_info("accept_file\n");
    char* buf = NULL;
    unsigned message_size = 0;
    
    if (Read_safe(client_fd, (char*) &message_size, sizeof(unsigned), key) < 0) {
        log_perror("read_size\n");
        return -1;
    }
    log_info("get_size message_size = %u\n", message_size);
    buf = (char*) Mycalloc(message_size, sizeof(char));
    if (Read_safe(client_fd, buf, message_size, key) < 0) {
        log_perror("recv_message\n");
        return -1;
    }
    
    char* path_name = strchr(strchr(input, ' ') + 1, ' ') + 1;
    *strchr(input, '\n') = '\0';
    log_info("path_name = %s: end\n", path_name);
    int file_fd = open(path_name, O_CREAT | O_WRONLY | O_TRUNC, 0666);
    if (file_fd < 0) {
        log_perror("open");
        return -1;
    }
    if (write(file_fd, buf, message_size) != message_size) {
        log_perror("write");
        return -1;
    }
    close(file_fd);
    free(buf);
    return 0;
}


int Send_file(char* input, int client_fd, int size, int is_udp, struct sockaddr_in* server, int key) {
    char* path_name = strchr(input, ' ') + 1;
    *strchr(path_name, ' ') = '\0';
    log_info("sending_file %s\n", path_name);
    struct stat statistica;
    int stat_error = stat(path_name, &statistica);
    if (stat_error < 0) {
        printf("No such file\n");
        return -1;
    }

    int file_fd = open(path_name, O_RDONLY);
    if (file_fd < 0) {
        log_perror("open");
        return -1;
    }
    
    char* buf = (char*) Mycalloc(statistica.st_size, sizeof(char));
    read(file_fd, buf, statistica.st_size);
    //log_info("file %s\n", buf);
    usleep(100000);
    unsigned message_size = statistica.st_size;
    log_info("st_size = %u\n", message_size);
    if (Sendto_safe(client_fd, READY_TO_ACCEPT, strlen(READY_TO_ACCEPT), 0, (struct sockaddr*) server, sizeof(*server), key) < 0) {
        log_perror("write ins Send_file");
        return -1;
    }
    usleep(100000);
    if (is_udp) {
        if (Sendto_safe(client_fd, (char*) &message_size, sizeof(unsigned), 0, (struct sockaddr*) server, sizeof(*server), key) < 0) {
            log_perror("write in Send_file");
            return -1;
        }
        usleep(100000);
        if (Sendto_safe(client_fd, buf, message_size, 0, (struct sockaddr*) server, sizeof(*server), key) < 0) {
            log_perror("write in Send_file");
            return -1;
        }
        log_info("was sended size = %d, mess = %s\n", message_size, buf);
        /*if (sendto(client_fd, buf, message_size, 0, (struct sockaddr*) server, sizeof(*server)) < 0) {
            log_perror("write in Send_file");
            return -1;
        }*/
    }
    else {
        if (Write_safe(client_fd, (char*) &message_size, sizeof(unsigned), key) < 0) {
            log_perror("write in Send_file");
            return -1;
        }
        usleep(100000);
        if (Write_safe(client_fd, buf, message_size, key) < 0) {
            log_perror("write in Send_file");
            return -1;
        }
    }
    
    log_info("ALL INFO ABOUT FILE SENDED\n");
    free(buf);
    return 0;
}

static int log_fd = -1;
static char buf_log[BUF_SIZE];


int print_time() {

    struct tm* c;
    time_t t;
    t = time(NULL);
    if (t == -1)
        exit(1);

    c = localtime(&t);
    if (!c)
        exit(1);
    return dprintf(log_fd, "%02d.%02d.%d %02d:%02d:%02d ", c -> tm_mday, c -> tm_mon, c -> tm_year, c -> tm_hour, c -> tm_min, c -> tm_sec);
}


int init_log(char* path) {
    static char* default_path = "/home/lev/Informatics_4_sem/SSH/src/log";

    log_fd = open(path ? path : default_path, O_CREAT | O_RDWR | O_APPEND, 0644);
    if (log_fd < 0) {
        perror("Cant open file\n");
        exit(1);
    }
    print_time();
    return dprintf(log_fd, "My favourite programm version 0x0. Succesfull log init.\n");
}


void print_log(char* str, ...) {
    va_list ap;
    va_start(ap, str);

    if (log_fd < 0)
        init_log(NULL);

    print_time();

    int ret = vsnprintf(buf_log, BUF_SIZE, str, ap);
    write(log_fd, buf_log, ret);

    va_end(ap);
}


void printf_fd(int fd, char* str, ...) {
    va_list ap;
    va_start(ap, str);
    char buf_printf[10000];
    if (fd < 0) {
            printf("no such file\n");
            exit(1);
        }

    int ret = vsnprintf(buf_printf, 10000, str, ap);
    write(fd, buf_printf, ret);

    va_end(ap);
}

void printf_fd_safe(int fd, int key, char* str, ...) {
    va_list ap;
    va_start(ap, str);
    char buf_printf[10000];
    if (fd < 0) {
            printf("no such file\n");
            exit(1);
        }

    int ret = vsnprintf(buf_printf, 10000, str, ap);
    Write_safe(fd, buf_printf, ret, key);

    va_end(ap);
}


int Encrypt(const char* info, int info_size, char** encrypted_info, FILE* pubKey_file) {
	log_info("Encrypt\n");
	RSA * pubKey = NULL;
	int outlen = 0;
	pubKey = PEM_read_RSAPublicKey(pubKey_file, NULL, NULL, NULL);
    if (pubKey == NULL) {
        log_perror("PEM_read_ probably problems with pubkey_file\n");
        exit(EXIT_FAILURE);
    }
	int encrypted_info_size = RSA_size(pubKey);
    if (info_size - 11 > encrypted_info_size) {
        log_error("Too big message for encrypting fo chosed size of public_key\n");
        exit(EXIT_FAILURE);
    }
	*encrypted_info = (char*) Mycalloc(encrypted_info_size, sizeof(char));
	OpenSSL_add_all_algorithms();
	outlen = RSA_public_encrypt(info_size, (const unsigned char*) info, (unsigned char*) *encrypted_info, pubKey, RSA_PKCS1_PADDING);
	if (outlen != RSA_size(pubKey)) {
		log_perror("RSA_public_encrypt\n");
		return -1;
	}
	return encrypted_info_size;
}

int Decrypt(const char* info, int info_size, char** decrypted_info, FILE* privKey_file) {
	log_info("Decrypt\n");
	RSA * privKey = NULL;
	int outlen = 0;
	OpenSSL_add_all_algorithms();
	privKey = PEM_read_RSAPrivateKey(privKey_file, NULL, NULL, SECRET);

	int key_size = RSA_size(privKey);
	*decrypted_info = (char *) Mycalloc(key_size, sizeof(char));

    //log_info("message to decrypt = %s\n, length = %d\n", info, info_size);
	outlen = RSA_private_decrypt(info_size, (const unsigned char*) info, (unsigned char*) *decrypted_info, privKey, RSA_PKCS1_PADDING);
	if (outlen < 0) {
		log_perror("RSA_private_decrypt, outlen = %d\n", outlen);
		return -1;
	}
	return outlen;
}


void Symmetric_encrypting(char* data, int size, int key) {
    log_info("Symmetric_ecnrypting: size = %d, %s\n", size, data);
    for (int i = 0; i < size; i++)
        data[i] = data[i] + key;
}


void Symmetric_decrypting(char* data, int size, int key) {
    for (int i = 0; i < size; i++)
        data[i] = data[i] - key;
    //log_info("Symmetric_decrypted size = %d: %s\n", size, data);
}


int Sendto_safe(int fd, const char* buf, size_t n, int flags, __CONST_SOCKADDR_ARG addr, socklen_t addr_len, int key) {
    char* buf_copy = Mycalloc(n, sizeof(char));
    strncpy(buf_copy, buf, n);
    Symmetric_encrypting(buf_copy, n, key);
    int ret = sendto(fd, buf_copy, n, flags, addr, addr_len);
    if (ret < 0) {
        log_perror("sendto\n");
        exit(EXIT_FAILURE);
    }
    free(buf_copy);
    return ret;
}


int Recvfrom_safe(int fd, char* buf, size_t n, int flags, __SOCKADDR_ARG addr, socklen_t *__restrict addr_len, int key) {
    int ret = recvfrom(fd, buf, n, flags, addr, addr_len);
    if (ret < 0) {
        log_perror("recvfrom\n");
        exit(EXIT_FAILURE);
    }
    Symmetric_decrypting(buf, ret, key);
    return ret;
}


int Read_safe(int fd, char* buf, size_t size, int key) {
    int ret = read(fd, buf, size);
    if (ret < 0) {
        log_perror("read\n");
        exit(EXIT_FAILURE);
    }
    Symmetric_decrypting(buf, ret, key);
    return ret;
}


int Write_safe(int fd, const char* buf, size_t size, int key) {
    char* buf_copy = Mycalloc(size, sizeof(char));
    strncpy(buf_copy, buf, size);
    Symmetric_encrypting(buf_copy, size, key);
    int ret = write(fd, buf_copy, size);
    if (ret < 0) {
        log_perror("write\n");
        exit(EXIT_FAILURE);
    }
    free(buf_copy);
    return ret;
}

void Set_child_death_signal() {
    if (prctl(PR_SET_PDEATHSIG, SIGTERM) < 0) {
        log_perror("prctl\n");
        exit(EXIT_FAILURE);
    }
}