#ifndef CLIENT_H
#define CLIENT_H

#include "exceptions.h"
#include "client-config.h"
#include "../shared/config.h"
#include "../shared/AbstractHost.h"
#include "../shared/message.h"
#include "../filemanager/FileManager.h"
#include "../security/BlockCipher.h"
#include "../security/HMAC.h"
#include "../security/certificate.h"
#include "../security/Hash.h"
#include "../security/DiffieHellman.h"
#include "../security/DigitalSignature.h"


using namespace std;

class Client : public AbstractHost
{

    sockaddr_in server_address;
    int sd_to_server;
    string client_name;
    DiffieHellman* dh;
    
    /**     virtual void onStdInput():
        ...
    */
    virtual void onStdInput();

    /**     virtual void onTimeout():
        ...
    */
    virtual void onTimeout();

    /**     virtual void onConnection(int sd):
        Called by connectToServer() when the connection is successfully 
        established. It extends AbstractHost::onConnection() by also
        setting sd_to_server.
    */
    virtual void onConnection(int sd);

    /**     virtual void onReceive(int sd, unsigned char buffer[], size_t n):
        ...
    */
    virtual void onReceive(int sd, unsigned char buffer[], size_t n);
    virtual void onDisconnection(int sd);
    
    command decode_command(string cmd);
    
    //create secure connection
    void on_recv_sign_hmac(unsigned char buffer[], size_t n);
    void on_ack_certificate(unsigned char buffer[], size_t n);

    //handlerUserCommand
    void read_local_file_list();
    void send_file(string file_name);
    void receive_file(string file_name);
    void read_remote_file_list();
    void print_commands();
    void undefined_command();

    //handlerProtocolClientServer
    void on_ack_send(string file_name);    
    void on_receive_list_file(unsigned char buffer[], size_t buffer_len);
    void delete_local_file(string file_name);
    void delete_remote_file(string file_name);
    void on_error(string message);
    void on_send_file_chunck(byte buffer[], size_t buffer_len);
    void on_send_last_block(byte buffer[], size_t buffer_len);
    void on_ack_delete(string message);
    void on_send_name_file(string file_name);

public:
    Client(string client_name, string server_ip, uint16_t port, time_t inactivity_sec = 0);
    ~Client();
    void connectToServer();

};

#endif