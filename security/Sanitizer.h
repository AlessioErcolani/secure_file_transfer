#ifndef SANITIZER_H
#define SANITIZER_H

#include <iostream>
#include <regex>

using namespace std;

class Sanitizer
{
public:
    static bool check_file_name(string filename);
};

#endif

