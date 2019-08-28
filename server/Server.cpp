#include "Server.h"

using namespace std;

Server::
Server(uint16_t port) : AbstractHost(0)
{
    if (port < 1024)
        Log::w("port may be reserved");
    
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);

    sd_listener = -1;

    dh = new DiffieHellman();

    ifstream file(USERS_FILE);
    for(string user_name; getline(file, user_name); )
        users.push_back(user_name);
    file.close();
}

Server::
~Server()
{
    if (dh)
        delete dh;
}

void
Server::
bindAndListen()
{
    int ret = -1;

    sd_listener = socket(AF_INET, SOCK_STREAM, 0);
    if (sd_listener == -1)
    {
        Log::e(string("cannot create listener socket: ") + strerror(errno));
        throw passive_socket_exception(strerror(errno));
    }
    Log::i("listener socket created");

    ret = bind(sd_listener, (sockaddr*) &address, sizeof(address));
    if (ret == -1)
    {
        Log::e(string("cannot bind address to listener socket: ") + strerror(errno));
        throw passive_socket_exception(strerror(errno));
    }
    Log::i("address and listener socket bound");

    ret = listen(sd_listener, BACKLOG);
    if (ret == -1)
    {
        Log::e(string("cannot declare listener socket as passive: ") + strerror(errno));
        throw passive_socket_exception(strerror(errno));
    }

    addFileDescriptor(sd_listener);

    Log::i("ready to receive connection requests");
}

void
Server::
onReadySocket(int sd)
{
    if (sd == sd_listener)
    {
        sockaddr_in client_address;
        memset(&client_address, 0, sizeof(client_address));
        socklen_t address_len = sizeof(client_address);
        
        int new_sd = accept(sd_listener, (sockaddr*) &client_address, &address_len);
        if (new_sd == -1)
        {
            Log::e(string("cannot accept new connect request: ") + strerror(errno));
            throw accept_exception(strerror(errno));
        }

        onConnection(new_sd);
        Log::i("new connection request successfully accepted");
    }
    else
        AbstractHost::onReadySocket(sd);
}

void
Server::
onConnection(int sd)
{
    AbstractHost::onConnection(sd);
}

void
Server::
onReceive(int sd, unsigned char buffer[], size_t n)
{
    SessionInformation* session = &connection_information.at(sd);

    try
    {
        if (socket_is_authenticated(sd))
        {
            switch(get_message_code(sd))
            {
                case SEND_NAME_FILE:
                    on_send_name_file(sd, string((char*)buffer));
                    break;
                case SEND_FILE_CHUNCK:
                    on_send_file_chunck(sd, buffer, n);
                    break;
                case LAST_BLOCK:
                    on_send_last_block(sd, buffer, n);
                    break;
                case ASK_LIST_FILE:
                    on_ask_file_list(sd);
                    break;
                case DELETE_FILE:
                    on_delete_file(sd, string((char*)buffer));
                    break;
                case RECEIVE_NAME_FILE:
                    on_recv_name_file(sd, string((char*)buffer));
                    break;
                case ACK_CODE_SEND:
                    on_ack_send(sd, string((char*)buffer));
                    break;

            }            
        }
        else 
        {
            switch (session->packet_number_received)
            {  

                case RECEIVE_PUB_KEY_CERTIFICATE_CLIENT:
                    on_recv_public_key_certificate_client(sd, buffer, n);
                    break;        

                case RECEIVE_SIGN_HMAC:
                    on_recv_signature_hmac(sd, buffer, n);
                    break;    

                default:
                    throw security_exception ("packet number unexpected");
            }
        }
    }
    catch (exception& e)
    {
        Log::e(e.what());
        onDisconnection(sd);
    }
    delete[] buffer;
}

void
Server::
onDisconnection(int sd)
{
    Log::i(TO_STR("client with socket descriptor " << sd << " disconnected"));
    recovery(sd);
    session_clear_information(sd);
    connection_information.erase(sd);
    AbstractHost::onDisconnection(sd);
}

void
Server::
onStdInput()
{
    Log::e("standard input is ignored on server side");
}

void
Server::
onTimeout()
{
    Log::e("timeout is ignored on server side");
}

void 
Server::
on_recv_public_key_certificate_client(int sd, byte buffer[], size_t n)
{
    Log::i(TO_STR("Creating a secure connection with socket: " << sd));

    SessionInformation* session = &connection_information.at(sd);

    size_t key_len = dh->get_key_length();
    size_t signature_len = 0;
    size_t digest_len = 0;

    Log::dump(TO_STR("Message 1 (" << n << " bytes)").c_str(), buffer, n);

    X509_CRL* crl = read_crl_PEM(CRL_FILE);
    if (!crl)
        throw security_exception("impossible to read crl");    

    X509* ca_certificate = read_certificate_PEM_from_file(CA_CERTIFICATE_FILE);
    if (!ca_certificate)
    {
        X509_CRL_free(crl);
        throw security_exception("impossible to read ca certificate");
    }

    X509_STORE* store = build_store(ca_certificate, crl);
    if (!store)
    {
        X509_CRL_free(crl);
        X509_free(ca_certificate);
        throw security_exception("impossible to build a store");
    }

    X509* client_certificate = cast_certificate_from_DER_format(buffer + key_len, n - key_len);
    if (!client_certificate)
    {
        X509_CRL_free(crl);
        X509_free(ca_certificate);
        X509_STORE_free(store);
        throw security_exception("impossible to cast the client certificate");
    }
    if (!verify_certificate(store, client_certificate))
    {   
        X509_free(ca_certificate);
        X509_CRL_free(crl);
        X509_free(client_certificate);
        X509_STORE_free(store);            
        throw security_exception("client certificate not valid");
    }

    X509_free(ca_certificate);
    X509_CRL_free(crl);
    X509_STORE_free(store);

    session->certificate = client_certificate;

    string users_to_check = X509_certificate_to_string(client_certificate);
    if (find(users.begin(), users.end(), users_to_check) == users.end())
    {
        X509_free(client_certificate);
        session->certificate = NULL;
        throw security_exception("client has not the permission to use the service");
    }

    byte* session_key = dh->compute_shared_key(buffer);          

    //compute k_conf and k_auth starting from Diffie-Hellman shared session key
    try
    {
        compute_conf_and_auth_keys(session_key, key_len, session->cipher, session->hmac);
    }
    catch(exception& e)
    {
        delete[] session_key;
        throw;
    }
    delete[] session_key;
    Log::i("Established k_conf and k_auth");

    EVP_PKEY* private_key = read_private_key_PEM(PRIVATE_KEY_FILE); 
    if (!private_key)
    {
        delete[] session_key;
        throw security_exception("impossible to read the private key");
    }

    signature_len = (size_t) EVP_PKEY_size(private_key);
    digest_len = session->hmac->getDigestSize();  
    size_t dimension_to_send = signature_len + digest_len + key_len;

    //Y_client||Y_server
    byte* public_keys_concatened = new byte[key_len * 2];
    byte* pub_key = dh->get_public_key();
    memcpy(public_keys_concatened,              buffer,     key_len);
    memcpy(public_keys_concatened + key_len,    pub_key,    key_len);

    DigitalSignature* pen = new SHA256_DigitalSignature();
    byte* signature = NULL;
    try
    {
        signature = pen->sign(public_keys_concatened, key_len*2, private_key);
    }
    catch(exception& e)
    {
        delete[] public_keys_concatened;
        delete pen;
        EVP_PKEY_free(private_key);
        throw security_exception(e.what());
    }
    EVP_PKEY_free(private_key);
    delete pen;

    byte* computed_digest = NULL;
    try
    {
        computed_digest = session->hmac->digest(signature, signature_len);
    }
    catch(exception& e)
    {
        delete[] public_keys_concatened;
        throw;
    }

    //read my certificate
    size_t certificate_len = 0;
    byte* my_certificate = cast_certificate_in_DER_format(SERVER_CERTIFICATE_FILE, certificate_len);
    if (!my_certificate)
        throw security_exception("impossible to read server's certificate");

    dimension_to_send += certificate_len;

    size_t msg_len = dimension_to_send + sizeof(size_t);

    // dim || Y_s || SIGN_server(Y_c||Y_s) || HMAC_sessionKey(Sign) || Cert
    byte* msg_to_client = new byte[msg_len];

    memcpy(msg_to_client,                                                           &dimension_to_send,    sizeof(size_t));    //dim
    memcpy(msg_to_client + sizeof(size_t),                                          pub_key,               key_len);           //Y_s
    memcpy(msg_to_client + sizeof(size_t) + key_len,                                signature,             signature_len);     //Sign
    memcpy(msg_to_client + sizeof(size_t) + key_len + signature_len,                computed_digest,       digest_len);        //Hmac
    memcpy(msg_to_client + sizeof(size_t) + key_len + signature_len + digest_len,   my_certificate,        certificate_len);   //Cert

    Log::dump(TO_STR("Message 2 (" << msg_len << " bytes)").c_str(), msg_to_client, msg_len);

    delete[] pub_key;
    delete[] signature;
    delete[] computed_digest;
    delete[] my_certificate;

    try
    {
        sendToHost(sd, msg_to_client, msg_len);
    }
    catch(exception& e)
    {
        delete[] msg_to_client;
        throw;
    }

    session->key_concatenated = public_keys_concatened;    
    delete[] msg_to_client;
}

void 
Server::
on_recv_signature_hmac(int sd, byte buffer[], size_t buffer_len)
{
    SessionInformation* session = &connection_information[sd];

    size_t key_len = dh->get_key_length();
    size_t signature_len = 0;
    size_t digest_len = 0;

    Log::dump(TO_STR("Message 3 (" << buffer_len << " bytes)").c_str(), buffer, buffer_len);

    EVP_PKEY* client_public_key = extract_public_key_from_X509(session->certificate);
    if (!client_public_key)
        throw security_exception("impossibible to read client certificate");

    signature_len = (size_t) EVP_PKEY_size(client_public_key);

    DigitalSignature* pen = new SHA256_DigitalSignature();
            
    bool success = false;
    try
    {
        success = pen->verify(buffer, session->key_concatenated, key_len * 2, client_public_key);
    }
    catch(exception& e)
    {
        delete pen;
        throw;
    }
   
    if (!success)
    {
        delete pen;
        throw security_exception("invalid signature");
    }

    delete session->key_concatenated;    
    session->key_concatenated = NULL;

    delete pen;

    string certificate_subject = get_subject_certificate(session->certificate);

    X509_free(session->certificate);
    session->certificate = NULL;    
    
    success = session->hmac->check_digest(buffer + signature_len, buffer, signature_len);
    if(!success)   
        throw security_exception("invalid HMAC");  
            
    session->initialization_phase_completed = true;

    string path_client_files = string(PATH_DIRECTORY) + certificate_subject;
    session->file_manager = new FileManager(PATH_DIRECTORY);
    session->file_manager->createDirectory(certificate_subject);                   
    session->file_manager->changePath(path_client_files);

    Log::i(TO_STR("Secure connection established with socket: " << sd));
}

void 
Server::
on_send_name_file(int sd, string file_name)
{
    byte* msg = NULL;
    byte* pt = NULL;
    size_t msg_len = 0;
    size_t pt_len = 0;

    if (!Sanitizer::check_file_name(file_name))
        throw security_exception("file name does not match regular expression");

    SessionInformation* session = &connection_information.at(sd);

    bool file_already_present = session->file_manager->isPresentFile(file_name);

    if (file_already_present)       
        session->file_manager->deleteFile(file_name);       //errors handle upper level
    
    session->file_manager->openFileWriteMode(file_name);    //errors handle upper level

    pt_len = file_name.length() + 1;
    pt = new byte[pt_len];
    memcpy(pt, file_name.c_str(), pt_len);
    header_t header_info(session->packet_number_sent, pt_len, ACK_CODE_SEND);
    try
    {                                                                          
        msg = prepare_message(&header_info, pt, pt_len, session->cipher, session->hmac, msg_len);  //note: pt_len will be overwritten with the actual payload length
        sendToHost(sd, msg, msg_len);
    }
    catch(exception& e)
    {
        delete[] pt;
        if (msg)
            delete[] msg;
        throw;
    }

    delete[] msg;
    delete[] pt;
}

void 
Server::
on_send_file_chunck(int fd, byte* buffer, size_t buffer_len)
{
    SessionInformation* session = &connection_information.at(fd);

    session->file_manager->writeBlock(buffer, buffer_len);      //handle errors upper level
}

void 
Server::
on_send_last_block(int fd, byte*buffer, size_t buffer_len)
{
    SessionInformation* session = &connection_information.at(fd);

    on_send_file_chunck(fd, buffer, buffer_len);               //handle errors upper level
    session->file_manager->closeFile();
}

void 
Server::
on_ask_file_list(int sd)
{
   
    size_t msg_len = 0;

    protocol code = RECEIVE_LIST_FILE_LAST;

    SessionInformation* session = &connection_information.at(sd);

    const vector<string>* list = session->file_manager->exploreDirectory();

    size_t pt_len = 0;
    int last_str_index = -1;
    byte* pt = NULL;
    byte* msg = NULL;
    
    //case: remote directory is empty
    if (list->size() == 0)  
    {
        string msg_error("remote directory is empty"); 
        pt_len = msg_error.length() + 1; 
        pt = new byte[pt_len];
        memcpy(pt, msg_error.c_str(), pt_len); 
        code = ERROR_CODE;
        header_t header_info(session->packet_number_sent, pt_len, code);    //note: pt_len will be overwritten with the actual payload length
        try
        {
            msg = prepare_message(&header_info, pt, pt_len, session->cipher, session->hmac, msg_len);
            sendToHost(sd, msg, msg_len);
        }
        catch(exception& e)
        {
            delete[] pt;
            if (msg)
                delete[] msg;
            throw;
        }

        delete[] msg;
        delete[] pt;

        return;
    }

    //general case
    int l = 0;
    int h = list->size() - 1;

    while (l < list->size())
    {
        pt_len = 0;
        //h initialization
        for (int i = l; i < list->size(); ++i)
        {
            size_t strlen_i = sizeof(unsigned short) + list->at(i).length() + 1;
            h = i;
            if (pt_len + strlen_i > MAX_LIST_SIZE)
            {
                h = i - 1;
                code = RECEIVE_LIST_FILE;
                break;
            }
            pt_len += strlen_i;
        }

        if (h == list->size() - 1)
            code = RECEIVE_LIST_FILE_LAST;    

        pt = new byte[pt_len];

        byte* head = pt;

        //prepare plaintext
        for (int i = l; i <= h; ++i)
        {
            unsigned short string_len = (unsigned short) list->at(i).length() + 1;  //length of str_i
            memcpy(head, &string_len, sizeof(unsigned short));                      //copy len_i
            head +=  sizeof(unsigned short);                                        //advance ptr (by 2)
            memcpy(head, list->at(i).c_str(), string_len);                          //copy str_i
            head = head + (size_t) string_len;                                      //advance ptr (by len_i)
        }

        header_t header_info(session->packet_number_sent, pt_len, code);            //note: pt_len will be overwritten with the actual payload length
        try
        {
            msg = prepare_message(&header_info, pt, pt_len, session->cipher, session->hmac, msg_len);
            sendToHost(sd, msg, msg_len);
        }
        catch(exception& e)
        {
            delete[] pt;
            if (msg)
                delete[] msg;
            throw;
        }

        delete[] msg;
        delete[] pt;

        l = h + 1; 
    }

}

void
Server::
on_delete_file(int sd, string file_name)
{
    SessionInformation* session = &connection_information.at(sd);

    size_t msg_len = 0;   
    size_t pt_len = 0;
    byte* msg = NULL;
    byte* pt = NULL;
    protocol code;

    if (!Sanitizer::check_file_name(file_name))
        throw security_exception("file name does not match regular expression");

    string body_msg;

    bool file_already_present = session->file_manager->isPresentFile(file_name);
    if (!file_already_present)
    {
        code = ERROR_CODE;
        body_msg = "file not present in the server";        
    }
    else
    {
        session->file_manager->deleteFile(file_name);               //erros handles upper level
        
        code = ACK_CODE_DELETE;
        body_msg = "file successfully deleted";
    }
        
    pt_len = body_msg.length() + 1;
    pt = new byte[pt_len];
    memcpy(pt, body_msg.c_str(), pt_len);

    header_t header_info(session->packet_number_sent, pt_len, code);   //note: pt_len will be overwritten with the actual payload length
    try
    {
        msg = prepare_message(&header_info, pt, pt_len, session->cipher, session->hmac, msg_len);
        sendToHost(sd, msg, msg_len);
    }
    catch(exception& e)
    {
        delete[] pt;
        if (msg)
            delete[] msg;
        throw;
    }

    delete[] msg;
    delete[] pt;

}

void
Server::
on_recv_name_file(int sd, string file_name)
{
    SessionInformation* session = &connection_information.at(sd);

    size_t msg_len = 0;   
    size_t pt_len = 0;
    byte* msg = NULL;
    byte* pt = NULL;
    protocol code;

    string body_msg;

    if (!Sanitizer::check_file_name(file_name))
        throw security_exception("file name does not match regular expression");

    bool success = session->file_manager->isPresentFile(file_name);
    if (!success)
    {
        code = ERROR_CODE;
        body_msg = "file not present in the server";        
    }
    else
    {        
        code = SEND_NAME_FILE;
        body_msg = file_name;
    } 

    pt_len = body_msg.length() + 1;
    pt = new byte[pt_len];
    memcpy(pt, body_msg.c_str(), pt_len);

    header_t header_info(session->packet_number_sent, pt_len, code);                            //note: pt_len will be overwritten with the actual payload length
    try
    {
        msg = prepare_message(&header_info, pt, pt_len, session->cipher, session->hmac, msg_len);
        sendToHost(sd, msg, msg_len);
    }
    catch(exception& e)
    {
        delete[] pt;
        if (msg)
            delete[] msg;
        throw;
    }

    delete[] msg;
    delete[] pt;

}

void
Server::
on_ack_send(int sd, string file_name)
{
    size_t msg_len = 0;
    size_t pt_len = 0;
    byte* pt = NULL;
    byte* msg = NULL;
    bool next_block_available = false;

    if (!Sanitizer::check_file_name(file_name))
        throw security_exception("file name does not match regular expression");

    SessionInformation* session = &connection_information.at(sd);
    session->file_manager->openFileReadMode(file_name);         //errors handle upper level

    pt = new byte[session->file_manager->getBlockSize()];
    try
    {
        next_block_available = session->file_manager->nextBlock();
        while (next_block_available)
        {
            pt_len = session->file_manager->readNextBlock(pt);

            next_block_available = session->file_manager->nextBlock();

            protocol code = next_block_available ? SEND_FILE_CHUNCK : LAST_BLOCK;
            header_t header_info(session->packet_number_sent, pt_len, code);                //note: pt_len will be overwritten with the actual payload length
            msg = prepare_message(&header_info, pt, pt_len, session->cipher, session->hmac, msg_len);

            sendToHost(sd, msg, msg_len);

            delete[] msg;
            msg = NULL;
        }

        delete[] pt;
        pt = NULL;

        session->file_manager->closeFile();
    }
    catch(const exception &e)
    {
        Log::e(e.what());
        if (pt)
            delete[] pt;
        if (msg)
            delete[] msg;
        throw;
    }
}