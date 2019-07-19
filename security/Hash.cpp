#include "Hash.h"

size_t
Hash::
getDigestSize()
{
    return (size_t) EVP_MD_size(getHashFunction());
}

byte*
Hash::
digest(byte msg[], size_t msg_size)
{

    unsigned int digest_size = (unsigned int) getDigestSize();

    int success = 0;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (ctx == NULL)
    {
        Log::e("null context, cannot produce digest");
        throw digest_exception ("null context, cannot produce digest");
    }

    success = EVP_DigestInit(ctx, getHashFunction());
    if(!success)
    {
        Log::e("cannot initialize digest");
        EVP_MD_CTX_free(ctx);
        throw digest_exception ("cannot initialize digest");
    }

    success = EVP_DigestUpdate(ctx, msg, msg_size);
    if(!success)
    {
        Log::e("cannot update digest");
        EVP_MD_CTX_free(ctx);
        throw digest_exception ("cannot update digest");
    }

    byte* digest = new byte[digest_size];
    memset((void*) digest, 0, digest_size);

    success = EVP_DigestFinal(ctx, digest, &digest_size);
    if(!success)
    {
        Log::e("cannot finalize digest");
        EVP_MD_CTX_free(ctx);
        delete[] digest;
        throw digest_exception ("cannot finalize digest");
    }

    EVP_MD_CTX_free(ctx);

    return digest;
}

bool
Hash::
check_digest(byte digest_to_check[], byte msg[], size_t msg_size)
{
    byte* computed_digest = digest(msg, msg_size);

    if (!computed_digest)
    {
        Log::e("error checking digests");
        return false;
    }

    int ret = CRYPTO_memcmp(computed_digest, digest_to_check, getDigestSize());

    if (ret != 0)
    {
        Log::w("digests do not correspond");
        Log::hex("digest to check", digest_to_check, getDigestSize());
        Log::hex("computed digest", computed_digest, getDigestSize());
    }
    
    delete[] computed_digest;

    return (ret == 0);

}