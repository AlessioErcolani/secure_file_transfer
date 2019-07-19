#include "log.h"
using namespace std;

LogLevel Log::level = LOG_INF;

void
Log::i(string msg, string tag, ostream& os)
{
    if (level <= LOG_INF)
        os << FGRN("INF") << " [" << tag << "]:\t" << msg << endl;
}

void
Log::w(string msg, string tag, ostream& os)
{
    if (level <= LOG_WRN)
        os << FYEL("WRN") << " [" << tag << "]:\t" << msg << endl;
}

void
Log::e(string msg, string tag, ostream& os)
{
    if (level <= LOG_ERR)
        os << FRED("ERR") << " [" << tag << "]:\t" << msg << endl;
}

void
Log::dump(const char * m, unsigned char * s, int n, FILE* f)
{
    if (dump_allowed && m && s && n > 0 && f)
    {
        fprintf(f, "%s [LOG]:\t%s\n", FBLU("DMP"), m);
        BIO_dump_fp(f, (const char *) s, n);
    }
}

void
Log::hex(const char * m, unsigned char * s, int n, FILE* f)
{
    if (dump_allowed && m && s && n > 0 && f)
    {
        fprintf(f, "%s [LOG]:\t%s\n", FBLU("HEX"), m);
        for (int i = 0; i < n; ++i)
            fprintf(f, "%02x", s[i]);
        fprintf(f, "%s\n", "");
    }
}

/*
Other option:
- Declare these constant strings (out of blocks):
    const string red("\033[0;31m");
    const string reset("\033[0m");
- Use operator<< this way:
    os << red << "ERR" << reset << " [" << tag << "]:\t" << msg << endl;
*/