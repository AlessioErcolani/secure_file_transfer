OBJECTS_C= ./client/*.cpp ./shared/*.cpp ./log/*.cpp ./filemanager/*.cpp ./security/*.cpp
OBJECTS_S= ./server/*.cpp ./shared/*.cpp ./log/*.cpp ./filemanager/*.cpp ./security/*.cpp

CC=g++

PROGRAM_NAME_C=Client.out
PROGRAM_NAME_S=Server.out

all: $(PROGRAM_NAME_C) $(PROGRAM_NAME_S)

$(PROGRAM_NAME_C):$(OBJECTS_C)
	$(CC) $(OBJECTS_C) -lcrypto -o $(PROGRAM_NAME_C)

$(PROGRAM_NAME_S):$(OBJECTS_S)
	$(CC) $(OBJECTS_S) -lcrypto -o $(PROGRAM_NAME_S)
