#include "Sanitizer.h"
using namespace std;

bool
Sanitizer::
check_file_name(string filename)
{
    //almeno un carattere alfanumerico (undescore incluso), poi un punto, poi da 1 a 6 caratteri alfanumerici (undescore escluso)
    regex filename_regex("[a-zA-Z0-9_]+[.]{1}[A-Za-z0-9]{1,6}");
    return regex_match(filename, filename_regex);
}
