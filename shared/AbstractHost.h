#ifndef ABSTRACT_HOST_H
#define ABSTRACT_HOST_H

#include <map>
#include <iostream>
#include <algorithm>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <climits>

#include "../log/log.h"
#include "../security/BlockCipher.h"
#include "../security/HMAC.h"
#include "../filemanager/FileManager.h"
#include "../security/certificate.h"
#include "SessionInformation.h"
#include "message.h"
#include "exceptions.h"

#define MAX_WRITABLE_BYTES ((size_t) 2*1024*1024*1024)

using namespace std;

int max(int a, int b);

const size_t MAX_PAYLOAD = 4096;

class AbstractHost
{
    bool end;
    int fd_i;
    int max_fd;
    fd_set master;
    fd_set read_set;
    
protected:
    map<int, SessionInformation> connection_information;
    time_t timeout_sec;
     
    void addFileDescriptor(int fd);
    void removeFileDescriptor(int fd);
    void endLoop();
    void session_clear_information(int fd);
    bool socket_is_authenticated(int fd);
    protocol get_message_code(int fd);
    void recovery(int sd);
    
    /**     virtual void onTimeout() = 0:
        Called by start() when the select()'s timeout expires. Must be 
        implemented by concrete subclasses.
    */
    virtual void onTimeout() = 0;

    /**     virtual void onStdInput() = 0:
        Called by start() when data is ready to be read from the standard input.
        Must be implemented by concrete subclasses.
    */
    virtual void onStdInput() = 0;

    /**     virtual void onReadySocket(int sd):
        Called by start() when when socket "sd" is ready to be read. If "sd" is 
        ready because the remote socket was closed then onDisconnection() is 
        called. Otherwise, if "sd" is ready beacause data has been received, 
        then onReceive() is called.
    */
    virtual void onReadySocket(int sd);
    
    /**     virtual void onConnection(int sd):
        Subclasses have to call this function when they connect to a remote 
        socket. It just adds the socket "sd" to the "master" set, but subclasses
        may extend this function.
    */
    virtual void onConnection(int sd);

    /**     virtual void onDisconnection(int sd):
        Called by onReadySocket() when the remote socket is closed. It just 
        removes and closes socket "sd", but subclasses may extend this function.
    */
    virtual void onDisconnection(int sd);

    /**     virtual void onReceive(int sd, unsigned char buffer[], size_t n) = 0:
        Called by onReadySocket() when some data has been received through "sd".
        Concrete subclasses must implement this function to specify what they 
        want to do with the data they receive.
    */
    virtual void onReceive(int sd, unsigned char buffer[], size_t n) = 0;
     
    virtual bool recvFromHost(int sd, unsigned char*& ptr, size_t& recv_bytes);

    virtual void sendToHost(int sd, unsigned char* buffer, size_t bytes_to_send);
    
    virtual bool recvMessage(int sd, byte*& pt, size_t& pt_len);
public:
    AbstractHost(time_t inactivity_sec = 0);
    ~AbstractHost();
    void start();
};

#endif