#include "AbstractHost.h"

using namespace std;

int
max(int a, int b)
{
    return (a > b) ? a : b;
}

AbstractHost::
AbstractHost(time_t inactivity_sec)
{
    if (inactivity_sec < 0)
    {
        Log::w("negative timeout passed to AbstractHost constructor");
        inactivity_sec = 0;
    }

    memset((void*) recv_buffer, 0, MAX_PAYLOAD);
    end = false;
    max_fd = -1;
    fd_i = 0;
    timeout_sec = inactivity_sec;
    FD_ZERO(&master);
    FD_ZERO(&read_set);
}

AbstractHost::
~AbstractHost()
{
    FD_ZERO(&master);
    FD_ZERO(&read_set);
}

void
AbstractHost::
addFileDescriptor(int fd)
{
    FD_SET(fd, &master);
    max_fd = max(max_fd, fd);
}

void
AbstractHost::
removeFileDescriptor(int fd)
{
    FD_CLR(fd, &master);
}

void
AbstractHost::
endLoop()
{
    end = true;
}

void
AbstractHost::
onConnection(int sd)
{
    addFileDescriptor(sd);
    SessionInformation session;
    connection_information.insert( pair<int,SessionInformation>(sd, session) );   
}

void
AbstractHost::
onDisconnection(int sd)
{
    removeFileDescriptor(sd);
    int ret = close(sd);
    if (ret == -1)
        Log::w("error while closing the socket");
}

void
AbstractHost::
sendToHost(int sd, unsigned char* buffer, size_t bytes_to_send)
{
    if (buffer == NULL)
        throw invalid_argument("invalid pointer for buffer parameter in sendToHost()");
    if (bytes_to_send == 0)
        throw invalid_argument("bytes_to_send parameter must be greater than 0 in recvFromHost()");
    if (bytes_to_send > MAX_PAYLOAD)
        throw invalid_argument("bytes_to_send cannot exceed MAX_PAYLOAD value");

    ssize_t bytes_sent = send(sd, (void*) buffer, bytes_to_send, 0);
    if (bytes_sent == -1)
    {
        Log::e(string("cannot send data to remote host: ") + strerror(errno));
        throw send_error(strerror(errno));
    }
    else if (bytes_sent < bytes_to_send)
    {
        Log::w("not all bytes have been sent");
        throw incomplete_send("not all bytes have been sent");
    }
    //else 
    //    Log::i(TO_STR("data sent (" << bytes_to_send << " bytes)"));

    connection_information[sd].packet_number_sent++;
}

bool
AbstractHost::
recvFromHost(int sd, unsigned char*& ptr, size_t& recv_bytes)
{
    ptr = NULL;
    recv_bytes = 0;

    ssize_t bytes_received = recv(sd, (void*) recv_buffer, MAX_PAYLOAD, 0);
    if (bytes_received == -1)
    {
        Log::e(string("could not receive data successfully: ") + strerror(errno));
        throw recv_error(strerror(errno));
    }
    else if (bytes_received == 0)
    {
        Log::i("remote socket has been closed");
        return false;
    }
    
    recv_bytes = (size_t) bytes_received;       //recv_bytes == expected_bytes_map[sd]
    ptr = new unsigned char[recv_bytes];        //allocate space
    memcpy(ptr, recv_buffer, recv_bytes);       //copy data
    memset((void*) recv_buffer, 0, recv_bytes); //clear recv_buffer (for security)

 //   Log::i(TO_STR("data received (" << bytes_received << " bytes)"));

    return true;
}

bool
AbstractHost::
recvMessage(int sd, byte*& pt, size_t& pt_len)
{
    pt = NULL;
    pt_len = 0;
    ssize_t bytes_received = 0;
    bool digests_match = false;

    SessionInformation* session = &connection_information.at(sd);

    //allocate space for header and digest
    size_t hd_len = HEADER_CONTENT_DIM + session->hmac->getDigestSize();
    byte* header = new byte[hd_len];

    //receive header (exactly hd_len bytes)
    bytes_received = recv(sd, (void*) header, hd_len, MSG_WAITALL);
    if (bytes_received == 0)
    {
        Log::i("remote socket has been closed");
        delete[] header;
        return false;
    }
    
    //check for header corruption
    digests_match = session->hmac->check_digest(header + DIGEST_OFFSET, header, HEADER_CONTENT_DIM);
    if (!digests_match)
    {
        delete[] header;
        throw security_exception("digest do not correspond");
    }

    //get payload length
    size_t pl_len = 0;
    memcpy(&pl_len, header + PAYLOAD_LEN_OFFSET, sizeof(size_t));
    
    //prepare space for header and payload (to compute digest later)
    byte* header_payload = new byte[hd_len + pl_len];   //create buffer
    memcpy(header_payload, header, hd_len);             //copy header at the beginning of the buffer
    byte* payload = &header_payload[hd_len];            //payload starts just after the header
    
    //receive payload (exactly pl_len bytes)
    bytes_received = recv(sd, (void*) payload, pl_len, MSG_WAITALL);
    if (bytes_received == 0)
    {
        delete[] header;
        delete[] header_payload;
        Log::i("remote socket has been closed");
        return false;
    }

    //receive digest
    byte* digest = new byte[session->hmac->getDigestSize()];
    bytes_received = recv(sd, (void*) digest, session->hmac->getDigestSize(), MSG_WAITALL);
    if (bytes_received == 0)
    {
        delete[] header;
        delete[] header_payload;
        delete[] digest;
        Log::i("remote socket has been closed");
        return false;
    }

    //check for message corruption
    digests_match = session->hmac->check_digest(digest, header_payload, hd_len + pl_len);
    if (!digests_match)
    {
        delete[] header;
        delete[] header_payload;
        delete[] digest;
        throw security_exception("digest do not correspond");
    }

    //decrypt payload
    try
    {
        session->cipher->decrypt(payload, pl_len, pt, pt_len);
    }
    catch(exception& e)
    {
        delete[] header;
        delete[] header_payload;
        delete[] digest;
        throw security_exception(e.what());
    }

    //message code
    protocol code;
    memcpy(&code, &header_payload[CODE_OFFSET], sizeof(protocol));
    session->last_command = code;    

    delete[] header;
    delete[] header_payload;
    delete[] digest;

    return true;
}

void
AbstractHost::
onReadySocket(int sd)
{
    unsigned char* ptr = NULL;
    size_t recv_bytes = 0;   
    
    connection_information[sd].packet_number_received++;

    if (socket_is_authenticated(sd))
    {
        try
        {
            if(!recvMessage(sd, ptr, recv_bytes))
            {
                onDisconnection(sd); 
                return;           
            }
        }
        catch (exception& e)
        {
            Log::e(e.what());
            delete[] ptr;
            onDisconnection(sd); 
            return;
        }
    }
    else
    {
        if (!recvFromHost(sd, ptr, recv_bytes))
        {
            onDisconnection(sd); 
            return;
        }
    }
    onReceive(sd, ptr, recv_bytes);     
}

void
AbstractHost::
start()
{
    timeval timeout;
    timeout.tv_sec = timeout_sec;
    timeout.tv_usec = 0;
    timeval* timeout_ptr = (timeout.tv_sec == 0) ? NULL : &timeout;

    while (!end)
    {
        read_set = master;
        
        int ret = select(max_fd+1, &read_set, NULL, NULL, timeout_ptr);
        if (ret < 0)
        {
            Log::e(strerror(errno));
            throw select_error(strerror(errno));
        }
        timeout.tv_sec = timeout_sec;
        timeout.tv_usec = 0;
        if (ret == 0)
        {
            Log::w("timeout expired");
            onTimeout();
            continue;
        }

        for (fd_i = 0; fd_i <= max_fd; fd_i++)
        {
            if (FD_ISSET(fd_i, &read_set))
            {
                if (fd_i == STDIN_FILENO)
                    onStdInput();
                else
                    onReadySocket(fd_i);
            }
        }
    }
}

bool 
AbstractHost::
socket_is_authenticated(int fd)
{
    return connection_information.at(fd).initialization_phase_completed;
}

void 
AbstractHost::
session_clear_information(int fd)
{
    SessionInformation* session = &connection_information.at(fd);

    if (session->key_concatenated)
    {
        delete[] session->key_concatenated;
        session->key_concatenated = NULL;
    }
    if (session->hmac)
    {
        delete session->hmac;
        session->hmac = NULL;
    }
    if (session->cipher)
    {
        delete session->cipher;
        session->cipher = NULL;
    }
    if (session->file_manager)
    {
        delete session->file_manager;
        session->file_manager = NULL;
    }
    if (session->certificate)
    {
        X509_free(session->certificate);
        session->certificate = NULL;
    }

}

protocol
AbstractHost::
get_message_code(int fd)
{   
    return connection_information.at(fd).last_command;   

}

void 
AbstractHost::
recovery(int fd)
{
    SessionInformation* session = &connection_information.at(fd);

    bool open_in_write_mode = false;
    string file_name_open;

    if (!session->file_manager->isClosed())
    {   
        open_in_write_mode = session->file_manager->isWritingMode();
        file_name_open = session->file_manager->getNameFileOpen();
        Log::i("File open. Trying to close it");
        session->file_manager->closeFile();
    }

    if (open_in_write_mode)
    {
        Log::i(TO_STR("Deleting: " << file_name_open).c_str());
        if(!session->file_manager->deleteFile(file_name_open))
            Log::e(TO_STR("Error in deleting: " << file_name_open).c_str());
    }
}