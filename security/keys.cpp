#include "keys.h"

using namespace std;

void compute_conf_and_auth_keys(byte shared_key[], size_t shared_key_len, BlockCipher*& cipher, hMAC*& hmac)
{
    Hash* hash = new Hash_SHA384();
    byte* digest_shared_key = NULL;

    //compute digest
    try
    {
        digest_shared_key = hash->digest(shared_key, shared_key_len);
    }
    catch(exception& e)
    {
        delete hash;
        throw;
    }

    //use least significant bits for k_auth and most significant bits for k_conf
    hmac = new SHA256_HMAC(digest_shared_key);                      //lsb
    cipher = new AES_128_CBC(digest_shared_key + hmac->KEY_SIZE);   //msb

    //delete buffers
    #pragma optimize("", off)
    memset((void*) digest_shared_key, 0, hash->getDigestSize());   //clear key (for security)
    memset((void*) shared_key, 0, shared_key_len);
    #pragma optimize("", on)

    delete[] digest_shared_key;
    delete hash;
}