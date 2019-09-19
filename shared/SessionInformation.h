struct SessionInformation
{
    bool initialization_phase_completed;
    unsigned int packet_number_sent;
    unsigned int packet_number_received;
    size_t written_bytes;
    byte* key_concatenated;
    hMAC* hmac;
    BlockCipher* cipher;
    FileManager* file_manager;
    protocol last_command;
    X509* certificate;

    SessionInformation()
    {
        initialization_phase_completed = false;
        packet_number_sent = 0; 
        packet_number_received = 0;
        written_bytes = 0;
        key_concatenated = NULL;
        hmac = NULL;
        cipher = NULL;
        certificate = NULL;
        file_manager = NULL;
        last_command = ERROR_CODE;
    }
};

