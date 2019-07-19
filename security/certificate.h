#ifndef CERTIFICATE_H
#define CERTIFICATE_H

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509_vfy.h>
#include <openssl/err.h>
#include <cstdlib>
#include <cstring>

#include "exceptions.h"
#include "../shared/config.h"
#include "../log/log.h"

using namespace std;

X509_STORE* build_store(X509* ca_certificate, X509_CRL* crl);
bool verify_certificate(X509_STORE* store, X509* certificate);
X509* read_certificate_PEM_from_file(const char* certificate_file);
X509_CRL* read_crl_PEM(const char* crl_file);
EVP_PKEY* read_public_key_PEM_from_file(const char* certificate_file);
X509* read_certificate_PEM_from_memory(byte* certificate_buffer);
EVP_PKEY* extract_public_key_from_X509(const X509* certificate);
string get_subject_certificate(X509* certificate);
byte* cast_certificate_in_DER_format(const char* certificate_name, size_t& certificate_len);
X509* cast_certificate_from_DER_format(byte buffer[], size_t certificate_len);

#endif