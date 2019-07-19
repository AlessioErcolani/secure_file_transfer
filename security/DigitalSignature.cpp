#include "DigitalSignature.h"

using namespace std;

byte*
DigitalSignature::
sign(byte msg[], size_t msg_size, EVP_PKEY* private_key)
{
    unsigned int signature_len = EVP_PKEY_size(private_key);
    int success = 0;    

    //create context
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if(!ctx)
    {
        Log::e("null context, cannot sign");
        throw sign_exception ("null context, cannot sign");
    }

    success = EVP_SignInit(ctx, getHashFunction());
    if(!success)
    {   
        Log::e("cannot initialize signature");
        EVP_MD_CTX_free(ctx);
        throw sign_exception ("cannot initialize signature");
    }

    success = EVP_SignUpdate(ctx, msg, msg_size);
    if(!success)
    {
        Log::e("cannot update signature");
        EVP_MD_CTX_free(ctx);
        throw sign_exception ("cannot update signature");
    }

    byte* signature = new byte[signature_len];

    success = EVP_SignFinal(ctx, signature, &signature_len, private_key);
    if(!success)
    {
        Log::e("cannot finalize signature");
        delete[] signature;
        EVP_MD_CTX_free(ctx);
        throw sign_exception ("cannot finalize signature");
    }
  
    EVP_MD_CTX_free(ctx);

    return signature;
}


bool
DigitalSignature::
verify(byte signature_to_verify[], byte msg[], size_t msg_size, EVP_PKEY* public_key)
{
    unsigned int signature_len = EVP_PKEY_size(public_key);
    int success = 0;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if(!ctx)
    {
        Log::e("null context, cannot sign");
        throw sign_exception ("null context, cannot sign");
    }

    success = EVP_VerifyInit(ctx, getHashFunction());
    if(!success)
    {
        Log::e("cannot initialize signature verify");
        EVP_MD_CTX_free(ctx);
        throw sign_exception ("cannot initialize signature verify");
    }

    success = EVP_VerifyUpdate(ctx, msg, msg_size);
    if(!success)
    {
        Log::e("cannot update signature verify");
        EVP_MD_CTX_free(ctx);
        throw sign_exception ("cannot update signature verify");
    }

    int verify = EVP_VerifyFinal(ctx, signature_to_verify, signature_len, public_key);

    if (verify == -1)
    {
        Log::e("error in verify final");
        EVP_MD_CTX_free(ctx);
        throw sign_exception ("error in verify final");
    }

    //free memory
    EVP_MD_CTX_free(ctx);

    return (verify == 1);
}

EVP_PKEY*
read_private_key_PEM(const char* private_key_file)
{
    FILE* file = fopen(private_key_file, "r");
    if (!file)
    {
        Log::e(string("Cannot open private key PEM file ") + string(private_key_file));
        return NULL;
    }

    EVP_PKEY* private_key = PEM_read_PrivateKey(file, NULL, NULL, NULL);

    fclose(file);

    if (!private_key)
        Log::e("Cannot read private key PEM file correctly");

    return private_key;
}