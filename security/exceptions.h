#ifndef SECURITY_EXCEPTIONS_H
#define SECURITY_EXCEPTIONS_H

#include <stdexcept>
#include <string>

using namespace std;

struct encryption_exception : public runtime_error
{
    encryption_exception(string const& msg) : runtime_error(msg) {}
};

struct decryption_exception : public runtime_error
{
    decryption_exception(string const& msg) : runtime_error(msg) {}
};

struct digest_exception : public runtime_error
{
    digest_exception(string const& msg) : runtime_error(msg) {}
};

struct sign_exception : public runtime_error
{
    sign_exception(string const& msg) : runtime_error(msg) {}
};




#endif