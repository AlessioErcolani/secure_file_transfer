#ifndef CONFIG_H
#define CONFIG_H

#define SERVER_ADDRESS "127.0.0.1"
#define PORT 8080
#define BACKLOG 10

typedef unsigned char byte;

enum protocol 
{
    SEND_NAME_FILE,
    ACK_CODE_SEND,
    SEND_FILE_CHUNCK, 
    DELETE_FILE, 
    LAST_BLOCK, 
    ASK_LIST_FILE, 
    RECEIVE_LIST_FILE, 
    ACK_CODE_DELETE,
    RECEIVE_NAME_FILE, 
    ERROR_CODE = -1
};

#endif