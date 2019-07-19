#ifndef MESSAGE_H
#define MESSAGE_H

#include "../security/HMAC.h"
#include "../security/BlockCipher.h"

#define PACKET_NUM_OFFSET   0
#define PAYLOAD_LEN_OFFSET  (PACKET_NUM_OFFSET + sizeof(unsigned int))
#define CODE_OFFSET         (PAYLOAD_LEN_OFFSET + sizeof(size_t))
#define DIGEST_OFFSET       (CODE_OFFSET + sizeof(int))

//size of the header (digest excluded)
#define HEADER_CONTENT_DIM  (sizeof(unsigned int) + sizeof(size_t) + sizeof(int))

struct header_t
{
    unsigned int packet_number;
    size_t payload_length;
    int message_code;

    header_t(unsigned int pkt_num, size_t pl_len, int code)
    {
        packet_number = pkt_num;
        payload_length = pl_len;
        message_code = code;
    }
};

byte* prepare_header(header_t* header_info, hMAC* hmac);
byte* prepare_message(header_t* header_info, byte pt[], size_t pt_len, BlockCipher* cipher, hMAC* hmac, size_t& msg_len);

#endif