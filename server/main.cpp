#include "Server.h"

using namespace std;

int
main()
{
    Log::i("I'm the server");

    Server s(PORT);
    s.bindAndListen();
    s.start();
    
    return 0;
}
