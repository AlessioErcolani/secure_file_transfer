#include "Client.h"

using namespace std;

Client::
Client(string client, string server_ip, uint16_t port, time_t inactivity_sec) : AbstractHost(inactivity_sec)
{
    sd_to_server = -1;
    memset(&server_address, 0, sizeof(server_address));

    if (port < 1024)
        Log::w("server port may be reserved for another application");

    const size_t max_address_size = strlen("xxx.xxx.xxx.xxx");
    if (server_ip.length() > max_address_size)
    {
        Log::e("server ip address is too long");
        throw invalid_argument("server ip address is too long");
    }

    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(port);
    int ret = inet_pton(AF_INET, server_ip.c_str(), &server_address.sin_addr);
    if (ret != 1)
    {
        memset(&server_address, 0, sizeof(server_address));
        Log::e("cannot convert network address");
        throw invalid_argument("server ip address is invalid");
    }

    addFileDescriptor(STDIN_FILENO);

    dh = new DiffieHellman();
    client_name = client;
   
}

Client::
~Client()
{
    delete dh;
}

void
Client::
connectToServer()
{
    int sd = socket(AF_INET, SOCK_STREAM, 0);
    if (sd == -1)
    {
        string error = string("cannot create socket to connect to server: ") + strerror(errno);
        Log::e(error);
        throw connection_exception(strerror(errno));
    }

    int ret = connect(sd, (sockaddr*) &server_address, sizeof(server_address));
    if (ret == -1)
    {
        string error = string("cannot connect to server: ") + strerror(errno);
        Log::e(error);
        throw connection_exception(strerror(errno));
    }

    onConnection(sd);
    Log::i("connected successfully to server");
}

void
Client::
onConnection(int sd)
{
    Log::i("Creating a secure connection...");
    sd_to_server = sd;
    AbstractHost::onConnection(sd);    

    X509* ca_certificate = read_certificate_PEM_from_file(CA_CERTIFICATE_FILE);
    if (!ca_certificate)
        throw security_exception("impossibile to read ca certificate");

    X509_CRL* crl = read_crl_PEM(CRL_FILE);
    if (!crl)
    {
        X509_free(ca_certificate);
        throw security_exception("impossibile to read crl");
    }

    X509_STORE* store = build_store(ca_certificate, crl);
    if (!store)
    {
        X509_free(ca_certificate);
        X509_CRL_free(crl);
        throw security_exception("impossibile to build a store");
    }

    X509* server_certificate = read_certificate_PEM_from_file(SERVER_CERTIFICATE_FILE);
    if (!server_certificate)
    {
        X509_free(ca_certificate);
        X509_CRL_free(crl);
        X509_STORE_free(store);
        throw security_exception("impossible to read server certificate");
    }

    if (!verify_certificate(store, server_certificate))
    {
        Log::e("server certificate not valid");
        X509_free(server_certificate);
        X509_free(ca_certificate);
        X509_CRL_free(crl);
        X509_STORE_free(store);
        throw security_exception("server certificate not valid");
    }

    X509_free(server_certificate);
    X509_free(ca_certificate);
    X509_CRL_free(crl);
    X509_STORE_free(store);

    byte* pub_key_dh = dh->get_public_key();
    try
    {
        sendToHost(sd_to_server, pub_key_dh, dh->get_key_length());
    }
    catch(exception& e)
    {
        delete[] pub_key_dh;
        throw;
    }
    
    delete[] pub_key_dh;

    Log::dump(TO_STR("Message 1 (" << pub_key_dh << " bytes)").c_str(), pub_key_dh, dh->get_key_length());

    connection_information.at(sd_to_server).file_manager = new FileManager(CLIENT_DIRECTORY_FILES);
}

void
Client::
onStdInput()
{
    string cmd;
    getline(cin, cmd);
    
    switch (decode_command(cmd))
    {
        case HELP:
            print_commands();
            break;

        case CLOSE:
            onDisconnection(sd_to_server);
            break;

        case READ_LOCAL_FILE_LIST:
            read_local_file_list();
            break;

        case UPLOAD_FILE:
            send_file(cmd.substr(5));
            break;

        case READ_REMOTE_FILE_LIST:
            read_remote_file_list();
            break;

        case REMOVE_LOCAL_FILE:
            delete_local_file(cmd.substr(8));
            break;

        case REMOVE_REMOTE_FILE:
            delete_remote_file(cmd.substr(8));
            break;

        case DOWNLOAD_FILE:
            receive_file(cmd.substr(8));
            break;

        default:
            undefined_command();
    }
}

void
Client::
onTimeout()
{
    onDisconnection(sd_to_server);
}

void
Client::
onReceive(int sd, unsigned char buffer[], size_t n)
{
    SessionInformation* session = &connection_information[sd];
    if (session->initialization_phase_completed)
    {
        switch(get_message_code(sd))
        {
            case ACK_CODE_SEND:
                on_ack_send(string((char*)buffer));
                break;

            case RECEIVE_LIST_FILE:
                on_receive_list_file(buffer, n);
                break;

            case ERROR_CODE:
                on_error(string((char*)buffer));
                break;

            case ACK_CODE_DELETE:
                on_ack_delete(string((char*)buffer));
                break;

            case SEND_NAME_FILE:
                on_send_name_file(string((char*)buffer));
                break;

            case SEND_FILE_CHUNCK:
                on_send_file_chunck(buffer, n);
                break;

            case LAST_BLOCK:
                on_send_last_block(buffer, n);
                break;
        }
    }
    else
    {
        try
        {
            switch(session->packet_number_received)
            {
                case RECEIVE_SIGN_HMAC:
                    on_recv_sign_hmac(buffer, n);
                    break;

                case ACK_CERTIFICATE:
                    on_ack_certificate(buffer, n);
                    break;
                
                default:
                    Log::e("I shouldn't be here !!!");
            }
        }
        catch(exception& e)
        {
            Log::e(e.what());
            delete[] buffer;
            onDisconnection(sd_to_server);
            return;
        }        
    }

    delete[] buffer;
}

command
Client::
decode_command(string cmd)
{
    if (cmd.compare("llist") == 0)
        return READ_LOCAL_FILE_LIST;

    if (cmd.compare("rlist") == 0)
        return READ_REMOTE_FILE_LIST;

    if (cmd.compare("help") == 0)
        return HELP;

    if (cmd.compare("llist") == 0)
        return READ_LOCAL_FILE_LIST;

    if ((cmd.substr(0,5)).compare("send ") == 0)
        return UPLOAD_FILE;

    if ((cmd.substr(0,8)).compare("ldelete ") == 0)
        return REMOVE_LOCAL_FILE;

    if ((cmd.substr(0,8)).compare("rdelete ") == 0)
        return REMOVE_REMOTE_FILE;

    if (cmd.compare("close") == 0)
        return CLOSE;

    if ((cmd.substr(0,8)).compare("receive ") == 0)
        return DOWNLOAD_FILE;

    return UNKNOWN;
}

void 
Client::
print_commands()
{
    char commands[][STRING_DIM] = 
    {
        "llist:\t\tlocal files list",
        "rlist:\t\tremote files list",
        "send <file_name>:\tupload the file",
        "receive <file_name>:\tdownload the file",
        "ldelete <file_name>:\tdelete the file locally",
        "rdelete <file_name>:\tdelete the file on the server",
        "help:\t\t\tprints the commands explanation",
        "close:\t\tclose the connection\n" 
    };

    cout<<"\nSECURE FILE TRANSFER:\n"<<endl;

    for (int i = 0; i < sizeof(commands)/STRING_DIM; ++i)    
        cout<<"\t> "<<commands[i]<<endl;

}

void 
Client::
on_recv_sign_hmac(unsigned char buffer[], size_t n)
{
    size_t key_length = dh->get_key_length();
    size_t signature_len = 0;

    SessionInformation* session = &connection_information.at(sd_to_server);

    Log::dump(TO_STR("Message 2 (" << n << " bytes)").c_str(), buffer, n);

    EVP_PKEY* server_public_key = read_public_key_PEM_from_file(SERVER_CERTIFICATE_FILE);
    if (!server_public_key)
        throw security_exception("impossible to read server public key");

    DigitalSignature* pen = new SHA256_DigitalSignature();
    
    signature_len = (size_t) EVP_PKEY_size(server_public_key);

    byte* msg_to_verify = new byte [key_length*2];

    //msg composed Y_server||SIGN_server(Y_client||Y_server)||HMAC_sessionKey(Sign)
    memcpy(msg_to_verify, dh->get_public_key(), key_length);
    memcpy(msg_to_verify + key_length, buffer, key_length);
    bool success = false;
    try
    {
        success = pen->verify(buffer + key_length, msg_to_verify, key_length*2, server_public_key);
    }
    catch(exception& e)
    {
        EVP_PKEY_free(server_public_key);
        delete[] msg_to_verify;
        delete pen;
        throw;
    }

    if (!success)
    {
        EVP_PKEY_free(server_public_key);
        delete[] msg_to_verify;
        delete pen;
        throw security_exception("invalid signature");
    }

    EVP_PKEY_free(server_public_key);
    delete pen;

    byte* session_key = dh->compute_shared_key(buffer);

    Hash* hash = new Hash_SHA512();
    byte* digest_session_key = NULL;
    try
    {
        digest_session_key = hash->digest(session_key, key_length);
    }
    catch(exception& e)
    {
        delete[] session_key;
        delete hash;
        EVP_PKEY_free(server_public_key);
        throw security_exception(e.what());
    }

    size_t half_digest_session_key_len = hash->getDigestSize()/2;

    session->hmac = new SHA256_HMAC(digest_session_key);                                    //lsb
    session->cipher = new AES_256_CBC(digest_session_key + half_digest_session_key_len);    //msb

    #pragma optimize("", off)
    memset((void*) digest_session_key, 0, hash->getDigestSize());   //clear key (for security)
    memset((void*) session_key, 0, key_length);
    #pragma optimize("", on)

    delete[] session_key;
    delete[] digest_session_key;
    delete hash;
     
    success = session->hmac->check_digest(buffer + key_length + signature_len, buffer + key_length, signature_len);
    if(!success)
    {
        delete[] msg_to_verify;
        throw security_exception("invalid HMAC");
    }

    size_t certificate_len = 0;
    
    string path = string(PATH_CERTIFICATE) + client_name + string (CERTIFICATE_EXTENSION);
    byte* certificate_bin = cast_certificate_in_DER_format(path.c_str(), certificate_len);
    if (!certificate_bin)
    {
        delete[] msg_to_verify;
        throw security_exception("impossible to read your certificate");
    }
    
    try
    {
        sendToHost(sd_to_server, certificate_bin, certificate_len);
    }
    catch(exception& e)
    {
        delete[] certificate_bin;
        delete[] msg_to_verify;
        throw;
    }

    delete[] certificate_bin;

    session->key_concatenated = msg_to_verify;

}

void 
Client::
on_ack_certificate(unsigned char buffer[], size_t n)
{
    size_t key_length = dh->get_key_length();
    size_t signature_len = 0;

    SessionInformation* session = &connection_information[sd_to_server];

    Log::dump(TO_STR("Message 4 (" << n << " bytes)").c_str(), buffer, n);
    
    string expected_msg(ACK);
    string recv_msg((char*)buffer);
    
    if(expected_msg.compare(recv_msg))
        throw security_exception("unexpected message");           
    
    string path(string(PATH_CERTIFICATE) + client_name + string(PRV_KEY_EXTENSION));

    EVP_PKEY* private_key = read_private_key_PEM(path.c_str());
    if (!private_key)    
        throw security_exception("impossible to read your private key");
    
    signature_len = (size_t) EVP_PKEY_size(private_key);
    
    DigitalSignature* pen = new SHA256_DigitalSignature();

    byte* signature = NULL;
    byte* computed_digest = NULL;
    try
    {
        signature = pen->sign(session->key_concatenated, key_length*2, private_key); 

        computed_digest = session->hmac->digest(signature, signature_len);
    }
    catch(exception& e)
    {
        if (signature)
            delete[] signature;
        if (computed_digest)
            delete[] computed_digest;
        delete pen;
        EVP_PKEY_free(private_key);
        throw;
    }

    EVP_PKEY_free(private_key);
    delete pen;

    size_t digest_size = session->hmac->getDigestSize();
    size_t msg_len = signature_len + digest_size;

    //msg SIGN_client(Y_client||Y_server)||HMAC(sign)_sessionKey
    byte* msg = new byte[msg_len];         
    memcpy(msg, signature, signature_len);
    memcpy(msg + signature_len, computed_digest, digest_size);

    Log::dump(TO_STR("Message 5 (" << msg_len << " bytes)").c_str(), msg, msg_len);

    try
    {
        sendToHost(sd_to_server,msg,msg_len);
    }
    catch(exception& e)
    {
        delete[] signature;
        delete[] computed_digest;
        delete[] msg;
        throw;
    }    

    delete[] signature;
    delete[] computed_digest;
    delete[] msg;    

    delete[] session->key_concatenated;
    session->key_concatenated = NULL;
    
    session->initialization_phase_completed = true;
    Log::i("Secure connection established!");

    print_commands();
}

void 
Client::
on_ack_send(string file_name)
{
    size_t msg_len = 0;
    size_t pt_len = 0;
    byte* pt = NULL;
    byte* msg = NULL;
    bool next_block_available = false;

    SessionInformation* session = &connection_information.at(sd_to_server);
    try
    {
    session->file_manager->openFileReadMode(file_name);
    } 
    catch (const exception &e) 
    { 
        Log::e(e.what());
        return;
    }

    cout << "\n\tstart sending: " << file_name << endl;;

    pt = new byte[session->file_manager->getBlockSize()];
    try
    {
        next_block_available = session->file_manager->nextBlock();
        while (next_block_available)
        {
            pt_len = session->file_manager->readNextBlock(pt);

            next_block_available = session->file_manager->nextBlock();

            protocol code = next_block_available ? SEND_FILE_CHUNCK : LAST_BLOCK;
            header_t header_info(session->packet_number_sent, pt_len, code);                            //note: pt_len will be overwritten with the actual payload length
            msg = prepare_message(&header_info, pt, pt_len, session->cipher, session->hmac, msg_len);

            sendToHost(sd_to_server, msg, msg_len);

            delete[] msg;
            msg = NULL;
        }

        delete[] pt;
        pt = NULL;

        session->file_manager->closeFile();
        cout << "\tfinish sending: " << file_name << "\n" << endl;;
    }
    catch(const exception &e)
    {
        Log::e(e.what());
        Log::e(TO_STR("Impossible to send: " <<file_name));
        if (msg)
            delete[] msg;
        if (pt)
            delete[] pt;
        onDisconnection(sd_to_server);
    }    
}

void
Client::
read_remote_file_list()
{   
    size_t msg_len = 0;

    byte pt[] = "list";
    size_t pt_len = sizeof(pt);
    byte* msg = NULL;

    SessionInformation* session = &connection_information.at(sd_to_server);

    header_t header_info(session->packet_number_sent, pt_len, ASK_LIST_FILE);
    msg = prepare_message(&header_info, pt, pt_len, session->cipher, session->hmac, msg_len);
    sendToHost(sd_to_server, msg, msg_len);   

    delete[] msg;
}

void 
Client::
on_receive_list_file(unsigned char buffer[], size_t buffer_len)
{
    cout << "\nfiles on the server: \n" <<endl;

    int index = 1;

    byte* end = buffer + buffer_len;
    byte* iterator = buffer;
    while (iterator != end)
    {
        unsigned short string_len;
        memcpy(&string_len, iterator, sizeof(unsigned short));
        iterator += sizeof(unsigned short);
        char* file_name = new char[string_len];
        memcpy(file_name, iterator, string_len);
        iterator += string_len;
        cout<<"\t> "<<index<<".\t"<<file_name<<endl;
        delete[] file_name;
        index++;
    }
    cout << endl;
}

void 
Client::
delete_local_file(string file_name)
{
    SessionInformation* session = &connection_information.at(sd_to_server);

    bool success = session->file_manager->isPresentFile(file_name);
    if (!success)
    {
        cerr<<"\n\t> file not present\n"<<endl;
        return;
    }

    success = session->file_manager->deleteFile(file_name);

    if (!success)
    {
        cerr<<"\n\t> error in delete the file\n"<<endl;
        return;
    }
    cout<<"\n\t> file successfully deleted\n"<<endl;
}

void 
Client::
delete_remote_file(string file_name)
{
    SessionInformation* session = &connection_information.at(sd_to_server);

    byte* msg = NULL;
    size_t msg_len = 0;

    size_t pt_len = file_name.size()+1;
    byte* pt = new byte[pt_len];
    memcpy(pt,(void*)file_name.c_str(),pt_len);    

    header_t header_info(session->packet_number_sent, pt_len, DELETE_FILE);    //note: pt_len will be overwritten with the actual payload length

    msg = prepare_message(&header_info, pt, pt_len, session->cipher, session->hmac, msg_len);

    sendToHost(sd_to_server, msg, msg_len);

    delete[] msg;
    delete[] pt;
}

void
Client::
on_error(string message)
{
    cout<<"\n\tServer > " << message << "\n" << endl;
}

void 
Client::
on_ack_delete(string message)
{
    cout << "\n\tServer > " << message << "\n" << endl;

}

void
Client::
undefined_command()
{
    cout << "\nCommand not found\n" << endl;
}

void
Client::
onDisconnection(int sd)
{
    recovery(sd_to_server);
    session_clear_information(sd_to_server);
    AbstractHost::onDisconnection(sd_to_server);
    AbstractHost::endLoop();
}

void 
Client::
read_local_file_list()
{   
    cout << endl;
    const vector<string>* list = connection_information.at(sd_to_server).file_manager->exploreDirectory();
    if (list->size() == 0)
        cout << "\t> the directory is empty" <<endl;
    for(int i = 0; i<list->size(); ++i)
        cout<<"\t> "<<(i+1)<<".\t"<<list->at(i)<<endl;
    cout <<endl;
}

void 
Client::
send_file(string file_name)
{
    SessionInformation* session = &connection_information[sd_to_server];

    if(!session->file_manager->isPresentFile(file_name))
    {
        cerr << "\t> file not present\n" << endl;;
        return;
    }

    byte* msg = NULL;
    size_t msg_len = 0;

    size_t pt_len = file_name.size()+1;
    byte* pt = new byte[pt_len];
    memcpy(pt,(void*)file_name.c_str(),pt_len);    

    header_t header_info(session->packet_number_sent, pt_len, SEND_NAME_FILE);                  //note: pt_len will be overwritten with the actual payload length

    msg = prepare_message(&header_info, pt, pt_len, session->cipher, session->hmac, msg_len);

    sendToHost(sd_to_server, msg, msg_len);

    delete[] msg;
    delete[] pt;
    
}

void 
Client::
receive_file (string file_name)
{
    SessionInformation* session = &connection_information.at(sd_to_server);

    size_t msg_len = 0;   
    size_t pt_len = 0;
    byte* msg = NULL;
    byte* pt = NULL;

    bool success = session->file_manager->isPresentFile(file_name);
    if (success)
    {
        string cmd;
        cout << "\n\tfile: " << file_name << " will be overwritten.Continue? (y/n)" <<  endl;
        getline(cin, cmd);
        if ((cmd.compare("n") == 0) || (cmd.compare("N") == 0))
            return;
        if ((cmd.compare("y") != 0) && (cmd.compare("Y") !=0))
        {
            undefined_command();
            return;
        }      
    }
            
    pt_len = file_name.length() + 1;
    pt = new byte[pt_len];
    memcpy(pt, file_name.c_str(), pt_len);

    header_t header_info(session->packet_number_sent, pt_len, RECEIVE_NAME_FILE);   //note: pt_len will be overwritten with the actual payload length
    msg = prepare_message(&header_info, pt, pt_len, session->cipher, session->hmac, msg_len);

    sendToHost(sd_to_server, msg, msg_len);

    delete[] msg;
    delete[] pt;
}

void
Client::
on_send_name_file(string file_name)
{
    byte* msg = NULL;
    byte* pt = NULL;
    size_t msg_len = 0;
    size_t pt_len = 0;

    SessionInformation* session = &connection_information.at(sd_to_server);

    bool file_already_present = session->file_manager->isPresentFile(file_name);

    if (file_already_present)
    {
        bool success = session->file_manager->deleteFile(file_name);
        if (!success)
            {
                cerr << "\n\terror on deleting the old version of the file\n" << endl;
                return;
            }         
    }

    try
    {
        session->file_manager->openFileWriteMode(file_name);
    }
    catch(exception& e)
    {
        cerr << "\n\terror on opening the file\n" << endl;
        return;
    }

    pt_len = file_name.length()+1;
    pt = new byte[pt_len];
    memcpy(pt, file_name.c_str(), pt_len);
    header_t header_info(session->packet_number_sent, pt_len, ACK_CODE_SEND);                   //note: pt_len will be overwritten with the actual payload length
    msg = prepare_message(&header_info, pt, pt_len, session->cipher, session->hmac, msg_len);

    sendToHost(sd_to_server, msg, msg_len);

    delete[] msg;
    delete[] pt;

    cout<<"\n\tstart receiving: " << file_name << endl;

}

void 
Client::
on_send_file_chunck(byte buffer[], size_t buffer_len)
{
    SessionInformation* session = &connection_information.at(sd_to_server);

    try
    {
        session->file_manager->writeBlock(buffer, buffer_len);
    }
    catch(exception& e)
    {
        Log::e(e.what());
        recovery(sd_to_server);
        session_clear_information(sd_to_server);
        AbstractHost::onDisconnection(sd_to_server);

    }

}

void
Client::
on_send_last_block(byte*buffer, size_t buffer_len)
{
    SessionInformation* session = &connection_information.at(sd_to_server);
    on_send_file_chunck(buffer, buffer_len); 
    string file_name = session->file_manager->getNameFileOpen();  
    session->file_manager->closeFile();
    cout<<"\tfinish receiving: " << file_name <<"\t\n" << endl;
}