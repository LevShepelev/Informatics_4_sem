#include <fcntl.h>
#include <stdlib.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <unistd.h>
#include "../include/lib.h"


int main() {
	RSA * rsa = NULL;
	unsigned long bits = 1024; 
	FILE * privKey_file = NULL, *pubKey_file = NULL;
	const EVP_CIPHER *cipher = NULL;
	privKey_file = fopen("./keys/private.key", "wb");
	pubKey_file = fopen("./keys/public.key", "wb");
    if (privKey_file == NULL || pubKey_file == NULL) {
        log_perror("fopen\n");
        exit(EXIT_FAILURE);
    }
	rsa = RSA_generate_key(bits, RSA_F4, NULL, NULL);
    if (rsa == 0) {
        log_perror("rsa_generate_key\n");
        exit(EXIT_FAILURE);
    }

	OpenSSL_add_all_ciphers();
	cipher = EVP_get_cipherbyname("bf-ofb");

    if (cipher == NULL) {
        log_perror("EVP_get_cipherbyname\n");
        exit(EXIT_FAILURE);
    }

	if (PEM_write_RSAPrivateKey(privKey_file, rsa, cipher, NULL, 0, NULL, SECRET) < 0) {
        log_perror("PEM_write_RSAPrivatyKey\n");
        exit(EXIT_FAILURE);
    }

	if (PEM_write_RSAPublicKey(pubKey_file, rsa) < 0) {
        log_perror("PEM_write_RSAPublicKey\n");
        exit(EXIT_FAILURE);
    }

	RSA_free(rsa);
	fclose(privKey_file);
	fclose(pubKey_file);
    printf("keys were successfully created\n");
    return 0;
}