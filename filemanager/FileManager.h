#ifndef FILEMANAGER_H
#define FILEMANAGER_H

#include <iostream>
#include <fstream>
#include <cstring>
#include <vector>
#include <algorithm>
#include <string>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <stdio.h>

#include "exceptions.h"
#include "../shared/config.h"

using namespace std;

#define DEFAULT_BLOCK_SIZE		1024
#define DEFAULT_PATH			"."

class FileManager{
    const size_t BLOCK_SIZE;
    string path_directory;
    vector<string> files_list;    
    enum state_file { READ, WRITE, CLOSE };
    state_file state;
    int head, tail;
    fstream file; 
    string file_name;

    void openFile(string file_name, state_file mode);
    string computePath(string file_name);
    
public:
	FileManager(string path_directory = DEFAULT_PATH, size_t block_size = DEFAULT_BLOCK_SIZE);
    const vector<string>* exploreDirectory();
    string getDirectoryPath();
    size_t getBlockSize();
    bool isPresentFile(string name);
    void changePath(string path);
	
    void openFileReadMode(string file_name);
    size_t readNextBlock(byte* buffer);
    bool nextBlock();
    bool isReadingMode();

    void openFileWriteMode(string file_name);
    void writeBlock(const byte* buffer, size_t size);    
    bool isWritingMode();

    void deleteFile(string file_name);

    void createDirectory(string directory_name);
	
    bool isClosed();
	void closeFile();

    string getNameFileOpen();

};

#endif