# Compiler, flags, etc.
CC = gcc
DEBUG = -g -O2
WFLAGS = -ansi -Wall -Wsign-compare -Wchar-subscripts -Werror
LDFLAGS = -Wl,-rpath,/usr/local/lib

# Libraries against which the object file for each utility should be linked
INCLUDES = /usr/include/
LIBS = /usr/lib/ 
#DCRYPTINCLUDE = /home/cslab/faculty/fazio/libdcrypt/include/
#DCRYPTLIB = /home/cslab/faculty/fazio/libdcrypt/lib/ 
DCRYPTINCLUDE = /usr/local/include/
DCRYPTLIB = /usr/local/lib/
#DMALLOC = -ldmalloc
GMP = -lgmp
DCRYPT = -ldcrypt

# The source file(s) for the each program
all: edu_keygen edu_encrypt edu_decrypt

edu_misc.o : edu_misc.c edu.h
	$(CC) $(DEBUG) $(WFLAGS) -I. -I$(INCLUDES) -I$(DCRYPTINCLUDE) -c edu_misc.c

edu_keygen.o  : edu_keygen.c edu_misc.c edu.h
	$(CC) $(DEBUG) $(WFLAGS) -I. -I$(INCLUDES) -I$(DCRYPTINCLUDE) -c edu_keygen.c edu_misc.c

edu_encrypt.o : edu_encrypt.c edu_misc.c edu.h
	$(CC) $(DEBUG) $(WFLAGS) -I. -I$(INCLUDES) -I$(DCRYPTINCLUDE) -c edu_encrypt.c edu_misc.c

edu_decrypt.o : edu_decrypt.c edu_misc.c edu.h
	$(CC) $(DEBUG) $(WFLAGS) -I. -I$(INCLUDES) -I$(DCRYPTINCLUDE) -c edu_decrypt.c edu_misc.c

edu_keygen: edu_keygen.o edu_misc.o
	$(CC) $(DEBUG) $(WFLAGS) -o $@ $@.o edu_misc.o -L. -L$(LIBS) -L$(DCRYPTLIB) $(DCRYPT) $(DMALLOC) $(GMP)

edu_encrypt: edu_encrypt.o edu_misc.o
	$(CC) $(DEBUG) $(WFLAGS) -o $@ $@.o edu_misc.o -L. -L$(LIBS) -L$(DCRYPTLIB) $(DCRYPT) $(DMALLOC) $(GMP)

edu_decrypt: edu_decrypt.o edu_misc.o
	$(CC) $(DEBUG) $(WFLAGS) -o $@ $@.o edu_misc.o -L. -L$(LIBS) -L$(DCRYPTLIB) $(DCRYPT) $(DMALLOC) $(GMP)

clean:
	-rm -f core *.core *.o *~ 

.PHONY: all clean
