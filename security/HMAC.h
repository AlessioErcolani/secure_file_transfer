#ifndef HMAC_H
#define HMAC_H

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <cstdlib>
#include <cstring>

#include "exceptions.h"
#include "../shared/config.h"
#include "../log/log.h"

using namespace std;

class hMAC
{
    
    const size_t KEY_SIZE;
public: 
byte* key;   
    hMAC(const byte* simmetric_key, size_t key_size);
    ~hMAC();
    virtual const EVP_MD* getHashFunction() = 0;
    size_t getDigestSize();
    byte* digest(byte msg[], size_t msg_size);
    bool check_digest(byte digest_to_check[], byte msg[], size_t msg_size);
};

#define SHA256_KEY_SIZE (256/8)
#define SHA512_KEY_SIZE (512/8)

class SHA256_HMAC : public hMAC
{
public:
    SHA256_HMAC(const byte* simmetric_key) : hMAC(simmetric_key, SHA256_KEY_SIZE) {};
    ~SHA256_HMAC();
    const EVP_MD* getHashFunction() {return EVP_sha256();};
};

class SHA512_HMAC : public hMAC
{
public:
    SHA512_HMAC(const byte* simmetric_key) : hMAC(simmetric_key, SHA512_KEY_SIZE) {};
    ~SHA512_HMAC();
    const EVP_MD* getHashFunction() {return EVP_sha512();};
};

#endif