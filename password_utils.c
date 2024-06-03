#include <argon2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "password_utils.h"

#define HASHLEN 32
#define SALTLEN 16
#define ENCODEDLEN 108

void generate_salt(uint8_t *salt, size_t length) {
    for (size_t i = 0; i < length; ++i) {
        salt[i] = rand() % 256;
    }
}

void hash_password(const char *password, const uint8_t *salt, char *hash) {
    uint8_t hash_bytes[HASHLEN];

    int result = argon2i_hash_raw(2, (1 << 16), 1, password, strlen(password), salt, SALTLEN, hash_bytes, HASHLEN);

    if (result != ARGON2_OK) {
        fprintf(stderr, "Error: %s\n", argon2_error_message(result));
        exit(EXIT_FAILURE);
    }

    for (int i = 0; i < HASHLEN; i++) {
        sprintf(hash + (i * 2), "%02x", hash_bytes[i]);
    }
}

int verify_password(const char *password, const uint8_t *salt, const char *hash_hex) {
    char computed_hash[HASHLEN * 2 + 1];
    hash_password(password, salt, computed_hash);

    return strcmp(computed_hash, hash_hex) == 0;
}
