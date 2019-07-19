#ifndef LOG_H
#define LOG_H

#include <iostream>
#include <ostream>
#include <stdio.h>
#include <string>
#include <openssl/err.h>
#include <sstream>

using namespace std;

#define TO_STR(x) static_cast<ostringstream&>((ostringstream() << dec << x)).str()

#define RST   "\x1B[0m"
#define KRED  "\x1B[31m"
#define KGRN  "\x1B[32m"
#define KYEL  "\x1B[33m"
#define KBLU  "\x1B[34m"
#define KMAG  "\x1B[35m"
#define KCYN  "\x1B[36m"
#define KWHT  "\x1B[37m"

#define FRED(x) KRED x RST
#define FGRN(x) KGRN x RST
#define FYEL(x) KYEL x RST
#define FBLU(x) KBLU x RST
#define FMAG(x) KMAG x RST
#define FCYN(x) KCYN x RST
#define FWHT(x) KWHT x RST

#define BOLD(x) "\x1B[1m" x RST
#define UNDL(x) "\x1B[4m" x RST

enum LogLevel
{
    LOG_INF,
    LOG_WRN,
    LOG_ERR,
    LOG_NONE
};

class Log
{
    static LogLevel level;
    static const bool dump_allowed = false;
public:
    static void i(string msg, string tag = "LOG", ostream& os = cout);
    static void w(string msg, string tag = "LOG", ostream& os = cout);
    static void e(string msg, string tag = "LOG", ostream& os = cerr);
    static void dump(const char * m, unsigned char * s, int n, FILE* f = stdout);
    static void hex(const char * m, unsigned char * s, int n, FILE* f = stdout);
};

#endif

