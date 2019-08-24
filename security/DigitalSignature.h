#ifndef DIGITAL_SIGNATURE_H
#define DIGITAL_SIGNATURE_H

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509_vfy.h>
#include <cstdlib>
#include <cstring>

#include "exceptions.h"
#include "../shared/config.h"
#include "../log/log.h"

using namespace std;

#define SIGN_SIZE (2048/8);

class DigitalSignature
{
public:
    DigitalSignature() {};
    ~DigitalSignature() {};

    virtual const EVP_MD* getHashFunction() = 0;

    byte* sign(byte msg[], size_t msg_size, EVP_PKEY* private_key);
    bool verify(byte signature_to_verify[], byte msg[], size_t msg_size, EVP_PKEY* public_key);
};

class SHA256_DigitalSignature : public DigitalSignature
{
public:
    SHA256_DigitalSignature() : DigitalSignature() {};
    ~SHA256_DigitalSignature() {};

    const EVP_MD* getHashFunction() {return EVP_sha256();};
};

EVP_PKEY* read_private_key_PEM(const char* private_key_file);

#endif