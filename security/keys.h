#ifndef KEYS_H
#define KEYS_H

#include "Hash.h"
#include "BlockCipher.h"
#include "HMAC.h"
#include "../shared/config.h"
#include "../log/log.h"

using namespace std;

//initialize "cipher" and "hmac" starting from a long "shared_key" whose length is "shared_key_len"
void compute_conf_and_auth_keys(byte shared_key[], size_t shared_key_len, BlockCipher*& cipher, hMAC*& hmac);

#endif