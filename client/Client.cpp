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

    //read CA's certificate
    ca_certificate = read_certificate_PEM_from_file(CA_CERTIFICATE_FILE);
    if (!ca_certificate)
    {
        Log::e("impossible to read CA's certificate");
        exit(1);
    }

    //read CRL
    crl = read_crl_PEM(CRL_FILE);
    if (!crl)
    {
        X509_free(ca_certificate);
        Log::e("impossible to read CRL");
        exit(1);
    }

    Log::i("CA's certificate and CRL read");

    //build a store
    store = build_store(ca_certificate, crl);
    if (!store)
    {
        X509_free(ca_certificate);
        X509_CRL_free(crl);
        Log::e("impossible to build a store");
        exit(1);
    }
   
}

Client::
~Client()
{
    if (dh)
        delete dh;

    X509_free(ca_certificate);
    X509_CRL_free(crl);
    X509_STORE_free(store);
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

    Log::i("Successfully connected to server");
    onConnection(sd);
}

void
Client::
onConnection(int sd)
{
    Log::i("Creating a secure connection...");
    sd_to_server = sd;
    AbstractHost::onConnection(sd);

    size_t certificate_len = 0;
    
    string path = string(PATH_CERTIFICATE) + client_name + string(CERTIFICATE_EXTENSION);
    byte* certificate_bin = cast_certificate_in_DER_format(path.c_str(), certificate_len);
    if (!certificate_bin)   
        throw security_exception("impossible to read your certificate");

    size_t pub_key_dh_len = dh->get_key_length();
    size_t dimension_to_send = pub_key_dh_len + certificate_len;
    size_t msg_len = dimension_to_send + sizeof(size_t);

    byte* pub_key_dh = dh->get_public_key();

    byte* msg = new byte[msg_len];

    memcpy(msg,                                     &dimension_to_send,         sizeof(size_t));
    memcpy(msg + sizeof(size_t),                    pub_key_dh,                 pub_key_dh_len);
    memcpy(msg + sizeof(size_t) + pub_key_dh_len,   certificate_bin,            certificate_len);
    
    try
    {
        sendToHost(sd_to_server, msg, msg_len);
    }
    catch(exception& e)
    {
        delete[] msg;
        delete[] pub_key_dh;
        delete[] certificate_bin;
        throw;
    }

    Log::dump(TO_STR("Message 1 (" << msg_len << " bytes)").c_str(), msg, msg_len);
    
    delete[] msg;
    delete[] pub_key_dh;
    delete[] certificate_bin;

    connection_information.at(sd_to_server).file_manager = new FileManager(CLIENT_DIRECTORY_FILES);
}

void
Client::
onStdInput()
{
    try
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
                send_file(cmd.substr(7));
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
                receive_file(cmd.substr(9));
                break;

            default:
                undefined_command();
        }
    }
    catch(exception& e)
    {
        Log::e(e.what());
        onDisconnection(sd_to_server);
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
    try
    {
        SessionInformation* session = &connection_information[sd];
        if (socket_is_authenticated(sd))
        {
            switch(get_message_code(sd))
            {
                case ACK_CODE_SEND:
                    on_ack_send(string((char*)buffer));
                    break;

                case RECEIVE_LIST_FILE_LAST: 
                    on_receive_list_file(buffer, n, true);
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

                default:
                    throw security_exception("message code unexpected");
            }
        }
        else
        {
            if (session->packet_number_received == RECEIVE_SIGN_HMAC)
                on_recv_sign_hmac(buffer, n);
            else
                throw security_exception("packet number unexpected");
        }
    }
    catch(exception& e)
    {
        Log::e(e.what());
        onDisconnection(sd_to_server);
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

    if ((cmd.substr(0,7)).compare("upload ") == 0)
        return UPLOAD_FILE;

    if ((cmd.substr(0,8)).compare("ldelete ") == 0)
        return REMOVE_LOCAL_FILE;

    if ((cmd.substr(0,8)).compare("rdelete ") == 0)
        return REMOVE_REMOTE_FILE;

    if (cmd.compare("close") == 0)
        return CLOSE;

    if ((cmd.substr(0,9)).compare("download ") == 0)
        return DOWNLOAD_FILE;

    return UNKNOWN;
}

void 
Client::
print_commands()
{
    char commands[][STRING_DIM] = 
    {
        "llist\t\t\t\t:local files list",
        "rlist\t\t\t\t:remote files list",
        "upload\t<file_name>\t:upload the file",
        "download\t<file_name>\t:download the file",
        "ldelete\t<file_name>\t:delete the file locally",
        "rdelete\t<file_name>\t:delete the file on the server",
        "help\t\t\t\t:prints the commands explanation",
        "close\t\t\t\t:close the connection\n" 
    };

    cout << "\nSECURE FILE TRANSFER:\n" << endl;

    for (int i = 0; i < sizeof(commands) / STRING_DIM; ++i)    
        cout << "\t> " << commands[i] << endl;

}

void 
Client::
on_recv_sign_hmac(unsigned char buffer[], size_t n)
{
    //define some lengths
    size_t key_length = dh->get_key_length();
    size_t sign_len = SIGN_SIZE;
    size_t hmac_len = SHA256_KEY_SIZE;
    size_t cert_len = n - key_length - sign_len - hmac_len;

    //define some useful aliases
    byte* ptr_y_s = buffer;
    byte* ptr_sign = buffer + key_length;
    byte* ptr_hmac = buffer + key_length + sign_len;
    byte* ptr_cert = buffer + key_length + sign_len + hmac_len;

    SessionInformation* session = &connection_information.at(sd_to_server);

    size_t signature_len = SIGN_SIZE;

    Log::dump(TO_STR("Message 2 (" << n << " bytes)").c_str(), buffer, n);

    //get server's certificate
    X509* server_certificate = cast_certificate_from_DER_format(ptr_cert, cert_len);
    if (!server_certificate)
        throw security_exception("impossible to cast server's certificate");

    //get server's public key from its certificate
    EVP_PKEY* server_public_key = extract_public_key_from_X509(server_certificate);
    if (!server_public_key)
        throw security_exception("impossible to read server's public key");

    //verify server's certificate
    if (!verify_certificate(store, server_certificate))
    {
        X509_free(server_certificate);
        throw security_exception("server certificate not valid");
    }

    //check server's name
    ifstream file(SERVERS_FILE);
    vector<string> servers;
    for (string server_name; getline(file, server_name); )
        servers.push_back(server_name);
    file.close();
    string servers_to_check = X509_certificate_to_string(server_certificate);
    if (find(servers.begin(), servers.end(), servers_to_check) == servers.end())
    {
        X509_free(server_certificate);
        throw security_exception("not legitimate server");
    }

    DigitalSignature* pen = new SHA256_DigitalSignature();

    byte* msg_to_verify = new byte[key_length*2];
    byte* my_dh_pub_key = dh->get_public_key();

    //msg: Y_server || SIGN_server(Y_client||Y_server) || HMAC_sessionKey(Sign), Cert_server
    memcpy(msg_to_verify,                   my_dh_pub_key,      key_length);
    memcpy(msg_to_verify + key_length,      buffer,             key_length);

    delete[] my_dh_pub_key;

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
  
    byte* session_key = dh->compute_shared_key(buffer);

    //compute k_conf and k_auth starting from Diffie-Hellman shared session key
    try
    {
        compute_conf_and_auth_keys(session_key, key_length, session->cipher, session->hmac);
    }
    catch(exception& e)
    {
        delete[] session_key;
        throw;
    }
    delete[] session_key;
    Log::i("Established k_conf and k_auth");

    
    try
    {
        success = session->hmac->check_digest(buffer + key_length + signature_len, buffer + key_length, signature_len);
    }
    catch(exception& e)
    {
        delete pen;
        delete[] msg_to_verify;
        throw;
    }
    if(!success)
    {
        delete pen;
        delete[] msg_to_verify;
        throw security_exception("invalid HMAC");
    }

    byte* key_concatenated = msg_to_verify;

    string path(string(PATH_CERTIFICATE) + client_name + string(PRV_KEY_EXTENSION));

    EVP_PKEY* private_key = read_private_key_PEM(path.c_str());
    if (!private_key)
    {   
        delete pen;
        throw security_exception("impossible to read your private key");
    }

    signature_len = (size_t) EVP_PKEY_size(private_key);
    
    byte* signature = NULL;
    byte* computed_digest = NULL;
    try
    {
        signature = pen->sign(key_concatenated, key_length * 2, private_key); 

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
    size_t dimension_to_send = signature_len + digest_size;
    size_t msg_len = dimension_to_send + sizeof(size_t);

    //dim||SIGN_client(Y_client||Y_server)||HMAC(sign)_sessionKey
    byte* msg = new byte[msg_len]; 
    memcpy(msg,                                     &dimension_to_send,         sizeof(size_t));        
    memcpy(msg +  sizeof(size_t),                   signature,                  signature_len);
    memcpy(msg +  sizeof(size_t) + signature_len,   computed_digest,            digest_size);

    Log::dump(TO_STR("Message 3 (" << msg_len << " bytes)").c_str(), msg, msg_len);

    try
    {
        sendToHost(sd_to_server, msg, msg_len);
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
    
    session->file_manager->openFileReadMode(file_name);    

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
    catch (exception& e)
    {
        Log::e(TO_STR("Impossible to send: " << file_name));
        if (msg)
            delete[] msg;
        if (pt)
            delete[] pt;
        throw;
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
    try
    {
        sendToHost(sd_to_server, msg, msg_len); 
    }
    catch(exception& e)
    {
        delete[] msg;
        throw;
    }
    delete[] msg;
}

void 
Client::
on_receive_list_file(unsigned char buffer[], size_t buffer_len, bool last)
{
    static int index = 0;
    byte* end = buffer + buffer_len;
    byte* iterator = buffer;
    while (iterator != end)
    {
        unsigned short string_len;
        memcpy(&string_len,     iterator,   sizeof(unsigned short));
        iterator += sizeof(unsigned short);
        char* file_name = new char[string_len];
        memcpy(file_name,       iterator,   string_len);
        iterator += string_len;
        cout << "\t> " << ++index << ".\t" << file_name << endl;
        delete[] file_name;
    }
    if (last)
    {
        cout << endl;
        index = 0;
    }
}

void 
Client::
delete_local_file(string file_name)
{
    SessionInformation* session = &connection_information.at(sd_to_server);

    bool success = session->file_manager->isPresentFile(file_name);
    if (!success)
    {
        cout << "\n\t> file not present\n" << endl;
        return;
    }

    try
    {
        session->file_manager->deleteFile(file_name);  
    }
    catch(exception& e)
    {
        cerr << "\n\t> problem in deleting file\n" << endl;
        return;
    }     

    cout << "\n\t> file successfully deleted\n" << endl;
}

void 
Client::
delete_remote_file(string file_name)
{
    SessionInformation* session = &connection_information.at(sd_to_server);

    byte* msg = NULL;
    size_t msg_len = 0;

    size_t pt_len = file_name.size() + 1;
    byte* pt = new byte[pt_len];

    memcpy(pt, (void*)file_name.c_str(), pt_len);    

    header_t header_info(session->packet_number_sent, pt_len, DELETE_FILE);    //note: pt_len will be overwritten with the actual payload length

    try
    {
        msg = prepare_message(&header_info, pt, pt_len, session->cipher, session->hmac, msg_len);
        sendToHost(sd_to_server, msg, msg_len);
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
Client::
on_error(string message)
{
    cout << "\n\tServer > " << message << "\n" << endl;
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
    Log::i("Disconnecting");
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
        cout << "\t> the directory is empty" << endl;
    for(int i = 0; i < list->size(); ++i)
        cout << "\t> " << (i + 1) << ".\t" << list->at(i) << endl;
    cout << endl;
}

void 
Client::
send_file(string file_name)
{
    SessionInformation* session = &connection_information.at(sd_to_server);

    if(!session->file_manager->isPresentFile(file_name))
    {
        cout << "\n\t> file not present\n" << endl;;
        return;
    }

    byte* msg = NULL;
    size_t msg_len = 0;

    size_t pt_len = file_name.size() + 1;
    byte* pt = new byte[pt_len];
    memcpy(pt, (void*)file_name.c_str(), pt_len);    

    header_t header_info(session->packet_number_sent, pt_len, SEND_NAME_FILE);                  //note: pt_len will be overwritten with the actual payload length

    try
    {
        msg = prepare_message(&header_info, pt, pt_len, session->cipher, session->hmac, msg_len);
        sendToHost(sd_to_server, msg, msg_len);
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
Client::
receive_file(string file_name)
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
    try
    {
        msg = prepare_message(&header_info, pt, pt_len, session->cipher, session->hmac, msg_len);
        sendToHost(sd_to_server, msg, msg_len);
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
        session->file_manager->deleteFile(file_name);

    session->file_manager->openFileWriteMode(file_name);

    pt_len = file_name.length() + 1;
    pt = new byte[pt_len];
    memcpy(pt, file_name.c_str(), pt_len);
    header_t header_info(session->packet_number_sent, pt_len, ACK_CODE_SEND);                   //note: pt_len will be overwritten with the actual payload length
    try
    {
        msg = prepare_message(&header_info, pt, pt_len, session->cipher, session->hmac, msg_len);
        sendToHost(sd_to_server, msg, msg_len);
    }
    catch(exception& e)
    {
        delete[] pt;
        if (msg)
            delete[] msg;
    }
    delete[] msg;
    delete[] pt;

    cout << "\n\tstart receiving: " << file_name << endl;
}

void 
Client::
on_send_file_chunck(byte buffer[], size_t buffer_len)
{
    SessionInformation* session = &connection_information.at(sd_to_server);

    session->file_manager->writeBlock(buffer, buffer_len);                  //errors handle upper level 
}

void
Client::
on_send_last_block(byte*buffer, size_t buffer_len)
{
    SessionInformation* session = &connection_information.at(sd_to_server);
    on_send_file_chunck(buffer, buffer_len);                                 //errors handles upper level  
    string file_name = session->file_manager->getNameFileOpen();  
    session->file_manager->closeFile();
    cout << "\tfinish receiving: " << file_name << "\t\n" << endl;
}