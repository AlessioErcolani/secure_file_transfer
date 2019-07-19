#include "message.h"

byte*
prepare_header(header_t* header_info, hMAC* hmac)
{
    size_t HEADER_DIM = HEADER_CONTENT_DIM + hmac->getDigestSize();
    byte* header = new byte[HEADER_DIM];

    //copy packet number, payload length and code into header
    memcpy(header + PACKET_NUM_OFFSET,  &header_info->packet_number,    sizeof(unsigned int));
    memcpy(header + PAYLOAD_LEN_OFFSET, &header_info->payload_length,   sizeof(size_t));
    memcpy(header + CODE_OFFSET,        &header_info->message_code,     sizeof(int));

    //compute digest of the header
    byte* digest = hmac->digest(header, HEADER_CONTENT_DIM);

    //append header's digest at the end of the header
    memcpy(header + DIGEST_OFFSET,      digest,         hmac->getDigestSize());

    delete[] digest;

    return header;
}

byte*
prepare_message(header_t* header_info, byte pt[], size_t pt_len, BlockCipher* cipher, hMAC* hmac, size_t& msg_len)
{
    msg_len = 0;
    byte* ct = NULL;
    size_t ct_len = 0;

    //encrypt the plaintext
    cipher->encrypt(pt, pt_len, ct, ct_len);

    //set the correct payload length in the header struct (it is unknown until now)
    header_info->payload_length = ct_len;

    //prepare the header
    byte* header = prepare_header(header_info, hmac);

    //allocate space for the message
    size_t hd_len = HEADER_CONTENT_DIM + hmac->getDigestSize();     //assuming digest size is the same for both header and message
    msg_len = hd_len + ct_len + hmac->getDigestSize();
    byte* msg = new byte[msg_len];

    //concatenate header and ciphertext
    memcpy(msg, header, hd_len);
    memcpy(msg + hd_len, ct, ct_len);

    //compute digest of (header, ciphertext) and concatenate it to ciphertext
    byte* digest = hmac->digest(msg, hd_len + ct_len);
    memcpy(msg + hd_len + ct_len, digest, hmac->getDigestSize());

    //free memory
    delete[] header;
    delete[] digest;
    delete[] ct;

    Log::dump("plaintext", pt, pt_len);
    Log::dump("message", msg, msg_len);

    return msg;
}