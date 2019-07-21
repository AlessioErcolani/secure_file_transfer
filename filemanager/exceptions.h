#ifndef FILE_MANAGER_H
#define FILE_MANAGER_H

#include <stdexcept>
#include <string>

using namespace std;

struct invalid_path_exception : public runtime_error
{
    invalid_path_exception(string const& msg) : runtime_error(msg) {}
};

struct file_already_open : public runtime_error
{
    file_already_open(string const& msg) : runtime_error(msg) {}
};

struct error_opening_file : public runtime_error
{
    error_opening_file(string const& msg) : runtime_error(msg) {}
};

struct illegal_mode : public runtime_error
{
    illegal_mode(string const& msg) : runtime_error(msg) {}
};

struct error_create_directory : public runtime_error
{
    error_create_directory(string const& msg) : runtime_error(msg) {}
};

struct error_delete_file : public runtime_error
{
    error_delete_file(string const& msg) : runtime_error(msg) {}
};


#endif