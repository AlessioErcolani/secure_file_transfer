#ifndef BLOCK_CIPHER_H
#define BLOCK_CIPHER_H

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <iostream>
#include <cstring>

#include "exceptions.h"
#include "../shared/config.h"
#include "../log/log.h"

using namespace std;

class BlockCipher
{
    byte* key;
public:
    const size_t KEY_SIZE;
    const size_t BLOCK_SIZE;

    BlockCipher(const byte* simmetric_key, size_t key_size, size_t block_size);
    ~BlockCipher();
    void encrypt(byte pt[], size_t pt_size, byte*& ct, size_t& ct_size, byte* iv = NULL);
    void decrypt(byte ct[], size_t ct_size, byte*& pt, size_t& pt_size, byte* iv = NULL);
    virtual const EVP_CIPHER* getCipherType() = 0;
};

#define AES_128_KEY_SIZE (128/8)
#define AES_128_BLOCK_SIZE (128/8)

class AES_128_ECB : public BlockCipher
{
public:
    AES_128_ECB(const byte* simmetric_key) : BlockCipher(simmetric_key, AES_128_KEY_SIZE, AES_128_BLOCK_SIZE) {};
    ~AES_128_ECB() {};
    const EVP_CIPHER* getCipherType() {return EVP_aes_128_ecb();};
};

#define AES_256_KEY_SIZE (256/8)
#define AES_256_BLOCK_SIZE (128/8)

class AES_256_ECB : public BlockCipher
{
public:
    AES_256_ECB(const byte* simmetric_key) : BlockCipher(simmetric_key, AES_256_KEY_SIZE, AES_256_BLOCK_SIZE) {};
    ~AES_256_ECB() {};
    const EVP_CIPHER* getCipherType() {return EVP_aes_256_ecb();};
};

class AES_256_CBC : public BlockCipher
{
public:
    AES_256_CBC(const byte* simmetric_key) : BlockCipher(simmetric_key, AES_256_KEY_SIZE, AES_256_BLOCK_SIZE) {};
    ~AES_256_CBC() {};
    const EVP_CIPHER* getCipherType() {return EVP_aes_256_cbc();};
};

#endif