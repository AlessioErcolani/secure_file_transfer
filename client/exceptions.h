#ifndef CLIENT_EXCEPTIONS_H
#define CLIENT_EXCEPTIONS_H

#include <stdexcept>
#include <string>

using namespace std;

struct connection_exception : public runtime_error
{
    connection_exception(string const& msg) : runtime_error(msg) {}
};

#endif

