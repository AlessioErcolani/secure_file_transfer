#ifndef HASH_H
#define HASH_H

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

class Hash
{
public:
    Hash() {};
    ~Hash() {};
    virtual const EVP_MD* getHashFunction() = 0;
    size_t getDigestSize();
    byte* digest(byte msg[], size_t msg_size);
    bool check_digest(byte digest_to_check[], byte msg[], size_t msg_size);
};

class Hash_SHA512 : public Hash
{
public:
    Hash_SHA512() : Hash() {};
    ~Hash_SHA512() {};
    const EVP_MD* getHashFunction() {return EVP_sha512();};
};

class Hash_SHA384 : public Hash
{
public:
    Hash_SHA384() : Hash() {};
    ~Hash_SHA384() {};
    const EVP_MD* getHashFunction() {return EVP_sha384();};
};

#endif