#include "FileManager.h"

FileManager::
FileManager(string path_directory, size_t block_size) : BLOCK_SIZE(block_size)
{
    if (!path_directory.length())
        throw invalid_argument("Path cannot be empty");
	this->path_directory = path_directory;
    state = CLOSE;
}

const vector<string>*
FileManager::
exploreDirectory()
{
    DIR* dir = opendir(path_directory.c_str());
    if (!dir)
    	throw invalid_path_exception("path not valid");
    files_list.clear();	
    dirent * dp;
    while ((dp = readdir(dir)) != NULL ) {
        if ( dp->d_name[0]=='.')
        	continue;
        files_list.push_back(string(dp->d_name));    
    }
    closedir(dir);
    return &files_list;
}

bool
FileManager::
isPresentFile(string file_name)
{
    exploreDirectory();
    return (find(files_list.begin(), files_list.end(), file_name)) != files_list.end();
}

string 
FileManager::
getDirectoryPath()
{
    return path_directory;
}

size_t
FileManager::
getBlockSize()
{
    return BLOCK_SIZE;
}

void
FileManager::
openFile(string file_name, state_file mode)
{
   
    if (!file_name.length())
        throw invalid_argument("file name cannot be empty");
    if (file.is_open())
        throw file_already_open("file already open");

    string path_file = computePath(file_name); 

    if (mode == READ)
        file.open(path_file.c_str(), fstream::binary | fstream::in );

    if (mode == WRITE)
        file.open(path_file.c_str(), fstream::binary | fstream::app);

    if (!file.is_open())
        throw error_opening_file("problem in file opening");

    this->file_name = file_name;
}

void
FileManager::
openFileReadMode(string file_name)
{
    openFile(file_name, READ);	
	head = tail = 0;
	state = READ;
}

size_t
FileManager::
readNextBlock(byte* buffer)
{
	if (!file.is_open())  
		throw file_already_open("File close");

	if (state != READ)
		throw illegal_mode("File not in read mode");

	if (!file.good())
		throw runtime_error("EOF reach"); 

	file.read((char*)buffer, BLOCK_SIZE);
	tail = head;
	head += file.gcount();				
	return head-tail;	
}

bool
FileManager::
nextBlock()
{
    return !file.eof();
}

bool
FileManager::
isReadingMode()
{
    return state == READ;
}

void
FileManager::
openFileWriteMode(string file_name)
{
	openFile(file_name, WRITE);
	state = WRITE;
}

void
FileManager::
writeBlock(const byte* buffer, size_t size)
{
	if (!file.is_open())  
        throw file_already_open("File close");
    if (state != WRITE)
        throw illegal_mode("File not in write mode");
	if (!file.good())
		throw runtime_error("Problem with the file");
	file.write((char*)buffer, size);
}

bool
FileManager::
isWritingMode()
{
    return state == WRITE;
}

bool
FileManager::
isClosed()
{
    return state == CLOSE;
}

void
FileManager::
closeFile()
{ 
	file.close();
    state = CLOSE;
    file_name.clear();
}

string
FileManager::
computePath(string file_name)
{
    string path_file=path_directory;
    path_file += "/" + file_name;
    return path_file;

}

void 
FileManager::
deleteFile(string file_name)
{
    if (!isClosed())
        throw illegal_mode("impossible to delete an open file");

    string path_file = computePath(file_name);

    if (remove(path_file.c_str()) != 0)
        throw error_delete_file(string("error in deleting: ") + file_name);
}

void 
FileManager::
createDirectory(string directory_name)
{
    int success = 0;

    string new_path = path_directory + directory_name;

    success = mkdir(new_path.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);

    if (success != 0)
        if (errno != EEXIST)
            throw error_create_directory("error creating directory");
}

void
FileManager::
changePath(string path)
{
    path_directory = path;
}

string 
FileManager::
getNameFileOpen()
{
    if(isClosed())
        throw runtime_error("file close");

    return file_name;
}