#include "Server.h"

using namespace std;

int
main()
{
    Log::i("I'm the server");

try
{

    Server s(PORT);
    s.bindAndListen();
    s.start();
} 
catch (exception& e)
{
    Log::e(e.what());
}
    
    return 0;
}
