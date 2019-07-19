#ifndef HOST_EXCEPTIONS_H
#define HOST_EXCEPTIONS_H

#include <stdexcept>
#include <string>

using namespace std;

struct select_error : public runtime_error
{
    select_error(string const& msg) : runtime_error(msg) {}
};

struct send_error : public runtime_error
{
    send_error(string const& msg) : runtime_error(msg) {}
};

struct incomplete_send : public runtime_error
{
    incomplete_send(string const& msg) : runtime_error(msg) {}
};

struct recv_error : public runtime_error
{
    recv_error(string const& msg) : runtime_error(msg) {}
};

struct incomplete_recv : public runtime_error
{
    incomplete_recv(string const& msg) : runtime_error(msg) {}
};

struct security_exception : public runtime_error
{
    security_exception(string const& msg) : runtime_error(msg) {}
};

#endif

