PREFIX=usr/bin
D=1
PRE="requirements.txt"
SRC=$(wildcard src/*.c)
LIBS=$(wildcard lib/*.c)
#SRC := $(filter-out src/parser.c, $(SRC))
OBJECTS=*.o
TNAME=c_otp
# compiler
CC=gcc
CFLAGS=-Wall
DEBUG=
WARNFLAGS=-Wsign-compare -Wint-conversion -fno-stack-protector
LDLIBS+=-lm -lcrypto -lgpgme
INCLUDE=-I lib
OBJECTS=$(patsubst %.c, %.o, $(SRC))
OBJECTS_LB=$(patsubst %.c, %.o, $(LIBS))
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


all: clean build $(OBJECTS) $(OBJECTS_LB)
	@echo Building the c_otp package
	$(CC) -o ${PREFIX}/$(TNAME) $(OBJECTS) $(OBJECTS_LB) $(LDLIBS) $(INCLUDE) $(WARNFLAGS)


clean:
	@echo Removing build directories
	rm -rf ${PREFIX}
	find . -name "*.o" -exec rm {} \;


install:
	@echo Installing the c_otp package on the system
	cp ${PREFIX}/c_otp ${TARGET}


%.o: %.c
	$(CC) -o $@ -c $< $(DEBUG) $(INCLUDE) $(WARNFLAGS)


$OBJECTS: $(SRC)
	$(CC) -c $(SRC) $(LDLIBS) $(INCLUDE) $(DEBUG) $(WARNFLAGS)


$OBJECTS_LB: $(OBJECTS_LB)
	$(CC) -c $(OBJECTS_LB) $(LDLIBS) $(INCLUDE) $(DEBUG) $(WARNFLAGS)


build:
	@mkdir -p ${PREFIX}


executable:
	$(CC) $(SRC) -o $(PREFIX)/c_otp $(LDLIBS) $(INCLUDE) $(DEBUG)


.PHONY: install
