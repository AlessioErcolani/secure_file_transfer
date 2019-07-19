#include "BlockCipher.h"

using namespace std;

BlockCipher::
BlockCipher(const byte* simmetric_key, size_t key_size, size_t block_size) : KEY_SIZE(key_size), BLOCK_SIZE(block_size)
{
    key = NULL;

    if (simmetric_key == NULL)
        throw invalid_argument("invalid NULL key");
    if (KEY_SIZE == 0)
        throw invalid_argument("invalid key size");
    if (BLOCK_SIZE == 0)
        throw invalid_argument("invalid key size");

    key = new byte[KEY_SIZE];
    memcpy((void*) key, (void*) simmetric_key, KEY_SIZE);
}

BlockCipher::
~BlockCipher()
{
    if (key)
    {   
        #pragma optimize("", off)
        memset((void*) key, 0, KEY_SIZE);   //clear key (for security)
        #pragma optimize("", on)
        delete[] key;
    }
}

void
BlockCipher::
encrypt(byte pt[], size_t pt_size, byte*& ct, size_t& ct_size, byte* iv)
{
    ct = NULL;
    ct_size = 0;

    if (key == NULL)
        throw invalid_argument("key has not been set, cannot encrypt");
    if (pt == NULL)
        throw invalid_argument("NULL plaintext, cannot encrypt");
    if (pt_size == 0)
        throw invalid_argument("cannot encrypt 0 bytes");

    int success = 0;
    int ct_len = 0;
    int ct_len_i = 0;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
    {
        Log::e("null context, cannot encrypt");
        throw encryption_exception("null context, cannot encrypt");
    }
    
    success = EVP_EncryptInit(ctx, getCipherType(), key, iv);
    if (!success)
    {
        Log::e("cannot initialize encryption");
        EVP_CIPHER_CTX_free(ctx);
        throw encryption_exception("cannot initialize encryption");
    }

    ct = new byte[pt_size + BLOCK_SIZE];                                //the sum cannot overflow
    
    success = EVP_EncryptUpdate(ctx, ct, &ct_len_i, pt, pt_size);
    if (!success)
    {
        Log::e("cannot update encryption");
        EVP_CIPHER_CTX_free(ctx);
        delete[] ct;
        throw encryption_exception("cannot update encryption");
    }
    ct_len += ct_len_i;

    success = EVP_EncryptFinal(ctx, ct + ct_len, &ct_len_i);
    if (!success)
    {
        Log::e("cannot finalize encryption");
        EVP_CIPHER_CTX_free(ctx);
        delete[] ct;
        throw encryption_exception("cannot finalize encryption");
    }
    ct_len += ct_len_i;

    EVP_CIPHER_CTX_free(ctx);

    ct_size = (size_t) ct_len;
}


void
BlockCipher::
decrypt(byte ct[], size_t ct_size, byte*& pt, size_t& pt_size, byte* iv)
{
    pt = NULL;
    pt_size = 0;

    if (key == NULL)
        throw invalid_argument("key has not been set, cannot decrypt");
    if (ct == NULL)
        throw invalid_argument("NULL ciphertext, cannot decrypt");
    if (ct_size == 0)
        throw invalid_argument("cannot decrypt 0 bytes");

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
    {
        Log::e("null context, cannot decrypt");
        throw decryption_exception ("null context, cannot decrypt");
    }
    
    int success = 0;
    int dt_len = 0;
    int dt_len_i = 0;
    
    success = EVP_DecryptInit(ctx, getCipherType(), key, iv);
    if (!success)
    {
        Log::e("cannot initialize decryption");
        EVP_CIPHER_CTX_free(ctx);
        throw decryption_exception ("cannot initialize decryption");
    }

    pt = new byte[ct_size];

    success = EVP_DecryptUpdate(ctx, pt, &dt_len_i, ct, ct_size);
    if (!success)
    {
        Log::e("cannot update decryption");
        EVP_CIPHER_CTX_free(ctx);
        delete[] pt;
        throw decryption_exception ("cannot update decryption");
    }
    dt_len += dt_len_i;

    success = EVP_DecryptFinal(ctx, pt + dt_len, &dt_len_i);
    if (!success)
    {
        Log::e("cannot finalize decryption");
        EVP_CIPHER_CTX_free(ctx);
        delete[] pt;
        throw decryption_exception ("cannot finalize decryption");
    }
    dt_len += dt_len_i;

    EVP_CIPHER_CTX_free(ctx);

    pt_size = (size_t) dt_len;
}