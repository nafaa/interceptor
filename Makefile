CC=gcc
CXX=g++
RM=rm -f
SYSLIB=-lssl -lcrypto -lpthread 
LDFLAGS+= $(SYSLIB)
MACRO= -DLINUX -DOPENSSL
SRC_DIR := src
OBJ_DIR := obj
SRC_FILES := $(wildcard $(SRC_DIR)/*.cpp)
OBJ_FILES := $(patsubst $(SRC_DIR)/%.cpp,$(OBJ_DIR)/%.o,$(SRC_FILES))
C_FILES := $(wildcard $(SRC_DIR)/*.c )
C_OBJ_FILES := $(patsubst $(SRC_DIR)/%.c ,$(OBJ_DIR)/%.o,$(C_FILES))

all: clean interceptor

interceptor: $(OBJ_FILES) $(C_OBJ_FILES) 
	$(CXX) $(MACRO) $(LDFLAGS) -o  $@ $^ $(SYSLIB)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp  
	$(CXX)  $(MACRO) $(CPPFLAGS) $(CXXFLAGS) -c -o $@ $<

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c 
	$(CC)  $(MACRO) $(CPPFLAGS) $(CXXFLAGS) -c -o $@ $<
 

clean:
	echo "Clean ..."
	$(RM) $(OBJ_FILES)/*
