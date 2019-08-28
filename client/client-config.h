#ifndef CLIENT_CONFIG_H
#define CLIENT_CONFIG_H

#define CLIENT_TIMEOUT          120
#define CA_CERTIFICATE_FILE "./client/certificates/Project CA_cert.pem"
#define CRL_FILE "./client/certificates/Project CA_crl.pem"
#define SERVER_CERTIFICATE_FILE "./client/certificates/Server_cert.pem"
#define PATH_CERTIFICATE "./client/certificates/"
#define CERTIFICATE_EXTENSION "_cert.pem"
#define PRV_KEY_EXTENSION "_key.pem"
#define ACK                "certificate received"
#define RECEIVE_SIGN_HMAC       1
#define STRING_DIM              100
#define CLIENT_DIRECTORY_FILES  "./client/files/"
#define SERVERS_FILE "./client/servers/servers.txt"

enum command 
{
    READ_LOCAL_FILE_LIST, 
    READ_REMOTE_FILE_LIST, 
    UPLOAD_FILE, 
    DOWNLOAD_FILE, 
    REMOVE_LOCAL_FILE, 
    REMOVE_REMOTE_FILE, 
    HELP, 
    UNKNOWN, 
    CLOSE
};

#endif