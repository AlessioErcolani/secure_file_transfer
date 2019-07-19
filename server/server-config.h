#ifndef SERVER_CONFIG_H
#define SERVER_CONFIG_H

#define CA_CERTIFICATE_FILE "./server/certificates/Project CA_cert.pem"
#define CRL_FILE "./server/certificates/Project CA_crl.pem"
#define PRIVATE_KEY_FILE "./server/certificates/Server_key.pem"
#define CERT_RECV   "certificate received"
#define PATH_DIRECTORY "./server/files/"
#define RECEIVE_PUB_KEY_CLIENT      1
#define RECEIVE_CERTIFICATE_CLIENT  2
#define RECEIVE_SIGN_HMAC           3

#endif
