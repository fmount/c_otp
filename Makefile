BIN=bin
D=1
PRE="requirements.txt"
SRC=$(wildcard src/*.c)
SRC := $(filter-out src/parser.c, $(SRC))
OBJECTS=*.o
TNAME=c_otp
# compiler
CC=gcc
CFLAGS=-Wall
DEBUG=
WARNFLAGS=-Wsign-compare
LDLIBS+=-lm -lcrypto
OBJECTS=$(patsubst %.c, %.o, $(SRC))
#LDFLAGS+=

#Enable debug mode: to do that set D=1
ifeq ($(D),1)
	DEBUG:=-DDEBUG
endif

#just for installation purposes
TARGET=/usr/bin

#used in compiler directives for development purposes
ifneq ($(wildcard .git/.),)
	GIT_HASH:=$(shell git describe --abbrev=4 --dirty --always --tags)
	DEFINES+=-DGIT_HASH=\"$(GIT_HASH)\"
endif


all: clean build $(OBJECTS)
	@echo Building the c_otp package
	$(CC) -o $(BIN)/$(TNAME) $(OBJECTS) $(LDLIBS)


clean:
	@echo Removing build directories
	rm -rf $(BIN)
	find . -name "*.o" -exec rm {} \;


install:
	@echo Installing the c_otp package on the system
	cp $(BIN)/c_otp $(TARGET)


%.o: %.c
	$(CC) -o $@ -c $< $(DEBUG)


$OBJECTS: $(SRC)
		 $(CC) -c $(SRC) $(LDLIBS) $(DEBUG)

build:
	@mkdir -p bin


executable:
	$(CC) $(SRC) -o $(BIN)/c_otp $(LDLIBS) $(DEBUG)


.PHONY: install
