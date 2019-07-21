#include "Client.h"

using namespace std;

int
main()
{
    Log::i("I'm the client");

    string chosen_client;

    while(true)
    {
        cout << "\nSIMULATION: choose a client \n\n\t1. Client1\n\t2. Client2" << endl;
        getline(cin, chosen_client);
        if ((chosen_client.compare("Client1") !=0) && (chosen_client.compare("Client2") != 0))
            Log::e("client does not exist");
        else
            break;
    }
    cout << endl;

    try
    {
        Client c(chosen_client, SERVER_ADDRESS, PORT, CLIENT_TIMEOUT);
        c.connectToServer();
        c.start();
    }
    catch (exception& e)
    {
        Log::e(e.what()); 
    }

    return 0;
}
