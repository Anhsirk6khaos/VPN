#include <stdio.h>
#include <string.h>
#include <openssl/hmac.h>

unsigned char* generate_hmac(unsigned char *key, unsigned char *data) {
    unsigned char* hmac;
    hmac = HMAC(EVP_sha256(), key, strlen((const char *)key), data, strlen((const char *)data), NULL, NULL);
    return hmac;
}

int compare_hmac(unsigned char *key, unsigned char *data, unsigned char *hmac) {
    unsigned char* new_hmac;
    new_hmac = generate_hmac(key, data);
    int i;
    for(i = 0; i < 32; i++) {
        if (hmac[i] != new_hmac[i]){
            return 0;
        }
    }

    return 1;
}
