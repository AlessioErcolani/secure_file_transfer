#ifndef SERVER_H
#define SERVER_H

#include "server-config.h"
#include "exceptions.h"
#include "../shared/config.h"
#include "../shared/AbstractHost.h"
#include "../filemanager/FileManager.h"
#include "../security/BlockCipher.h"
#include "../security/HMAC.h"
#include "../security/Hash.h"
#include "../security/DiffieHellman.h"
#include "../security/DigitalSignature.h"
#include "../security/certificate.h"

using namespace std;

class Server : public AbstractHost
{
    int sd_listener;
    sockaddr_in address;
    //creation secure connection
    void on_recv_public_key_client(int sd, byte buffer[], size_t buffer_len);
    void on_recv_certificate_client(int sd, byte buffer[], size_t buffer_len);
    void on_recv_signature_hmac(int sd, byte buffer[], size_t buffer_len);

    //protocolClientServer    
    void on_send_name_file(int sd, string file_name);
    void on_ack_send(int sd, string file_name);
    void on_recv_name_file(int sd, string file_name);
    void on_send_file_chunck(int sd, byte buffer[], size_t buffer_len);
    void on_send_last_block(int sd, byte buffer[], size_t buffer_len);
    void on_ask_file_list(int sd);
    void on_delete_file(int sd, string file_name);

protected:
    DiffieHellman* dh;
    /**     virtual void onReadySocket(int sd):
        ...
    */
    virtual void onReadySocket(int sd);

    /**     virtual void onStdInput():
        A Server ignores standard input, so it just prints a message.
    */
    virtual void onStdInput();

    /**     virtual void onStdInput():
        A Server has no timeout to expire, so it just prints a message.
    */
    virtual void onTimeout();

    /**     virtual void onConnection(int sd):
        Called by onReadySocket() when the connection is successfully 
        established. It extends AbstractHost::onConnection() by also
        setting handling the map with session information.
    */
    virtual void onConnection(int sd);

    /**     virtual void onDisconnection(int sd):
        ...
    */
    virtual void onDisconnection(int sd);

    /**     virtual void onReceive(int sd, unsigned char buffer[], size_t n):
        ...
    */
    virtual void onReceive(int sd, unsigned char buffer[], size_t n);
public:
    Server(uint16_t port);
    ~Server();
    void bindAndListen();
};

#endif
