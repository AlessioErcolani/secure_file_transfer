#ifndef SERVER_EXCEPTIONS_H
#define SERVER_EXCEPTIONS_H

#include <stdexcept>
#include <string>

using namespace std;

struct passive_socket_exception : public runtime_error
{
    passive_socket_exception(string const& msg) : runtime_error(msg) {}
};

struct accept_exception : public runtime_error
{
    accept_exception(string const& msg) : runtime_error(msg) {}
};

#endif

