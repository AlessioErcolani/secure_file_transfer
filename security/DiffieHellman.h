#ifndef DIFFIE_HELLMAN_H
#define DIFFIE_HELLMAN_H

#include <openssl/dh.h>
#include <openssl/bn.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <string.h>
#include <openssl/hmac.h>
#include "../shared/config.h"
#include "../log/log.h"

class DiffieHellman
{
    DH* dh;
    BIGNUM *P, *G;
    byte* public_key;

    void get_dh2048();
    void reset_dh();
public:
    DiffieHellman();
    ~DiffieHellman();

    byte* get_public_key();
    byte* compute_shared_key(byte peer_public_key[]);
    size_t get_key_length();
};
#endif