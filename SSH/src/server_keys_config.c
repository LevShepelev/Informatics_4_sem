#include <fcntl.h>
#include <stdlib.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <unistd.h>
#include "../include/lib.h"
#define PUB_EXP 65537


int main() {
    printf("to create server keys press 1, to create client keys press 2\n");
    int a = 0;
    char dir_name[20] = {'\0'};
    scanf("%d", &a);
    if (a == 1)
        strcpy(dir_name, "server_keys");
    else if (a == 2)
        strcpy(dir_name, "client_keys");
    else {
        printf("incorrect usage\n");
        return -1;
    }
	RSA * rsa = NULL;
	unsigned long bits = 1024; 
	FILE * privKey_file = NULL, *pubKey_file = NULL;
	const EVP_CIPHER *cipher = NULL;
    char name_private[4096], name_public[4096];
    strcpy(name_private, dir_name);
    strcpy(name_public, dir_name);
    mkdir(dir_name, 0777);
	privKey_file = fopen(strcat(strcat(name_private, "/"), "private.key"), "wb");
	pubKey_file = fopen(strcat(strcat(name_public, "/"),  "public.key"), "wb");
    if (privKey_file == NULL || pubKey_file == NULL) {
        log_perror("fopen\n");
        exit(EXIT_FAILURE);
    }

    BIGNUM *bne = NULL;
    bne = BN_new();
    
    if (BN_set_word(bne, PUB_EXP) < 0) {
        log_info("Bn_set_word\n");
    }
    rsa = RSA_new();
    if (RSA_generate_key_ex(rsa, bits, bne, NULL) < 0) {
        log_perror("RSA_generate_key\n");
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