#include "HMAC.h"

using namespace std;

hMAC::
hMAC(const byte* simmetric_key, size_t key_size) : KEY_SIZE(key_size)
{
    key = NULL;

    if (simmetric_key == NULL)
        throw invalid_argument("invalid NULL key");
    if (KEY_SIZE == 0)
        throw invalid_argument("invalid key/block size");

    key = new byte[KEY_SIZE];
    memcpy((void*) key, (void*) simmetric_key, KEY_SIZE);
}

hMAC::
~hMAC()
{
    if (key)
    {
        #pragma optimize("", off)
        memset((void*) key, 0, KEY_SIZE);   //clear key (for security)
        #pragma optimize("", on)
        delete[] key;
    }
}


size_t
hMAC::
getDigestSize()
{
    return (size_t) EVP_MD_size(getHashFunction());
}


byte*
hMAC::
digest(byte msg[], size_t msg_size)
{
    if (key == NULL)
        throw invalid_argument("key has not been set, cannot produce digest");
    if (msg == NULL)
        throw invalid_argument("NULL message, cannot produce digest");
    if (msg_size == 0)
        throw invalid_argument("cannot produce digest of a 0 bytes message");

    unsigned int digest_size = (unsigned int) getDigestSize();

    int success = 0;

    HMAC_CTX* mdctx = HMAC_CTX_new();
    if (mdctx == NULL)
    {
        Log::e("null context, cannot produce digest");
        throw digest_exception ("null context, cannot produce digest");
    }

    success = HMAC_Init_ex(mdctx, key, KEY_SIZE, getHashFunction(), NULL);
    if(!success)
    {
        Log::e("cannot initialize digest");
        HMAC_CTX_free(mdctx);
        throw digest_exception ("cannot initialize digest");
    }

    success = HMAC_Update(mdctx, msg, msg_size);
    if(!success)
    {
        Log::e("cannot update digest");
        HMAC_CTX_free(mdctx);
        throw digest_exception ("cannot update digest");
    }

    byte* digest = new byte[digest_size];

    success = HMAC_Final(mdctx, digest, &digest_size);
    if(!success)
    {
        Log::e("cannot finalize digest");
        HMAC_CTX_free(mdctx);
        delete[] digest;
        throw digest_exception ("cannot finalize digest");
    }

    HMAC_CTX_free(mdctx);

    return digest;
}

bool
hMAC::
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