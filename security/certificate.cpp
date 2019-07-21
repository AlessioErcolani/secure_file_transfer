#include "certificate.h"

using namespace std;

X509_STORE*
build_store(X509* ca_certificate, X509_CRL* crl)
{
    int ret = 0;

    // create store
    X509_STORE* store = X509_STORE_new();
    if (!store)
    {
        string error(ERR_error_string(ERR_get_error(), NULL));
        Log::e(string("Unable to build store: ") + error);
        return NULL;
    }

    // add CA's certificate
    ret = X509_STORE_add_cert(store, ca_certificate);
    if (ret != 1)
    {
        string error(ERR_error_string(ERR_get_error(), NULL));
        Log::e(string("Unable to add CA's certificate to store: ") + error);
        X509_STORE_free(store);
        return NULL;
    }

    // add CRL
    ret = X509_STORE_add_crl(store, crl);
    if (ret != 1)
    {
        string error(ERR_error_string(ERR_get_error(), NULL));
        Log::e(string("Unable to add CA's certificate to store: ") + error);
        X509_STORE_free(store);
        return NULL;
    }

    // set flags
    ret = X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK);
    if (ret != 1)
    {
        string error(ERR_error_string(ERR_get_error(), NULL));
        Log::e(string("Unable set flags of store: ") + error);
        X509_STORE_free(store);
        return NULL;
    }

    return store;
}

string
get_subject_certificate(X509* certificate)
{   
    string common_name("CN=");
    string subject(X509_NAME_oneline(X509_get_subject_name(certificate), NULL, 0));

    size_t position_in_string = subject.find(common_name);
    string cut_string = subject.substr(position_in_string + common_name.length());
    position_in_string = cut_string.find("/");

    return cut_string.substr(0, position_in_string - 1);
}

bool
verify_certificate(X509_STORE* store, X509* certificate)
{
    int ret = 0;

    X509_STORE_CTX* store_ctx = X509_STORE_CTX_new();
    if(!store_ctx)
    {
        string error(ERR_error_string(ERR_get_error(), NULL));
        Log::e(string("Unable to create store context: ") + error);
        return false;
    }

    ret = X509_STORE_CTX_init(store_ctx, store, certificate, NULL);
    if(ret != 1)
    {
        string error(ERR_error_string(ERR_get_error(), NULL));
        Log::e(string("X509_STORE_CTX_init() failed: ") + error);
        X509_STORE_CTX_free(store_ctx);
        return false;
    }

    string subject(X509_NAME_oneline(X509_get_subject_name(certificate), NULL, 0));
    string issuer(X509_NAME_oneline(X509_get_issuer_name(certificate), NULL, 0));

    string msg = TO_STR("Certificate of \"" << subject << "\" (released by \"" << issuer << "\" ");

    ret = X509_verify_cert(store_ctx);
    
    X509_STORE_CTX_free(store_ctx);

    if(ret != 1)
    {
        Log::w(msg + "could NOT be verified");
        return false;
    }

    Log::i(msg + "verified successfully");
    return true;
}

X509*
read_certificate_PEM_from_file(const char* certificate_file)
{
    FILE* file = fopen(certificate_file, "r");
    if (!file)
    {
        Log::e(string("Cannot open certificate PEM file ") + string(certificate_file));
        return NULL;
    }

    X509* certificate = PEM_read_X509(file, NULL, NULL, NULL);

    fclose(file);

    if (!certificate)
        Log::e("Cannot read certificate PEM file correctly");

    return certificate;
}

X509_CRL*
read_crl_PEM(const char* crl_file)
{
    FILE* file = fopen(crl_file, "r");
    if (!file)
    {
        Log::e(string("Cannot open CRL PEM file ") + string(crl_file));
        return NULL;
    }

    X509_CRL* crl = PEM_read_X509_CRL(file, NULL, NULL, NULL);

    fclose(file);

    if (!crl)
        Log::e("Cannot read CRL PEM file correctly");

    return crl;
}

EVP_PKEY*
read_public_key_PEM_from_file(const char* certificate_file)
{
    const X509* certificate = read_certificate_PEM_from_file(certificate_file);
    if (!certificate)
    {
        Log::e(string("Cannot read public key file ") + string(certificate_file));
        return NULL;
    }

    EVP_PKEY* public_key = X509_get0_pubkey(certificate);
    if (!public_key)
    {
        Log::e(string("Cannot get public key from certificate ") + string(certificate_file));
        return NULL;
    }

    return public_key;
}

EVP_PKEY* 
extract_public_key_from_X509(const X509* certificate)
{
    if(!certificate)
    {
        Log::e("certificate NULL");
        return NULL;
    }

    EVP_PKEY* public_key = X509_get0_pubkey(certificate);

    if (!public_key)
    {
        Log::e(string("Cannot get public key from certificate "));
        return NULL;
    }

    return public_key;
}

byte* 
cast_certificate_in_DER_format(const char* certificate_name, size_t& certificate_len)
{
    X509* certificate = read_certificate_PEM_from_file(certificate_name);
    if (!certificate)
    {
        Log::e(string("Cannot read public key file "));
        return NULL;
    }

    byte* certificate_DER = NULL;

    int size_certificate = i2d_X509(certificate, &certificate_DER);

    if (size_certificate < 0)
    {
        Log::e(string("Cannot convert in DER format "));
        return NULL;

    }

    certificate_len = (size_t) size_certificate;

    return certificate_DER;
}

X509*
cast_certificate_from_DER_format(byte buffer[], size_t certificate_len )
{
    return d2i_X509(NULL, (const byte**)&buffer, certificate_len);

}

string
X509_certificate_to_string(const X509* certificate)
{
    return string (X509_NAME_oneline(X509_get_subject_name(certificate), NULL, 0)); 
}
