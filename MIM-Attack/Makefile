# Compiler, flags, etc.
CC = gcc
DEBUG = -g -O2
WFLAGS = -ansi -Wall -Wsign-compare -Wchar-subscripts #-Werror
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
all : mtm_pki mtm_alice mtm_bob mtm_launcher mtm_mallory

edu_misc.o : edu_misc.c edu.h
	$(CC) $(DEBUG) $(WFLAGS) -I. -I$(INCLUDES) -I$(DCRYPTINCLUDE)  -c edu_misc.c

mtm_cert.o : mtm_cert.c mtm.h edu.h
	$(CC) $(DEBUG) $(WFLAGS) -I. -I$(INCLUDES) -I$(DCRYPTINCLUDE)  -c mtm_cert.c

mtm_prot.o : mtm_prot.c mtm.h edu.h
	$(CC) $(DEBUG) $(WFLAGS) -I. -I$(INCLUDES) -I$(DCRYPTINCLUDE)  -c mtm_prot.c

mtm_pki.o : mtm_pki.c mtm.h edu.h
	$(CC) $(DEBUG) $(WFLAGS) -I. -I$(INCLUDES) -I$(DCRYPTINCLUDE)  -c mtm_pki.c

mtm_pki : mtm_pki.o mtm_cert.o edu_misc.o
	$(CC) $(DEBUG) $(WFLAGS) -o $@ $@.o mtm_cert.o edu_misc.o -L. -L$(LIBS) -L$(DCRYPTLIB) $(DCRYPT) $(DMALLOC) $(GMP)

mtm_launcher.o : mtm_launcher.c mtm.h edu.h
	$(CC) $(DEBUG) $(WFLAGS) -I. -I$(INCLUDES) -I$(DCRYPTINCLUDE)  -c mtm_launcher.c

mtm_launcher : mtm_launcher.o mtm_prot.o mtm_cert.o edu_misc.o
	$(CC) $(DEBUG) $(WFLAGS) -o $@ $@.o mtm_prot.o mtm_cert.o edu_misc.o -L. -L$(LIBS) -L$(DCRYPTLIB) $(DCRYPT) $(DMALLOC) $(GMP)

mtm_alice.o : mtm_alice.c mtm.h edu.h
	$(CC) $(DEBUG) $(WFLAGS) -I. -I$(INCLUDES) -I$(DCRYPTINCLUDE)  -c mtm_alice.c

mtm_alice : mtm_alice.o mtm_prot.o mtm_cert.o edu_misc.o
	$(CC) $(DEBUG) $(WFLAGS) -o $@ $@.o mtm_prot.o mtm_cert.o edu_misc.o -L. -L$(LIBS) -L$(DCRYPTLIB) $(DCRYPT) $(DMALLOC) $(GMP)

mtm_bob.o : mtm_bob.c mtm.h edu.h
	$(CC) $(DEBUG) $(WFLAGS) -I. -I$(INCLUDES) -I$(DCRYPTINCLUDE)  -c mtm_bob.c

mtm_bob : mtm_bob.o mtm_prot.o mtm_cert.o edu_misc.o
	$(CC) $(DEBUG) $(WFLAGS) -o $@ $@.o mtm_prot.o mtm_cert.o edu_misc.o -L. -L$(LIBS) -L$(DCRYPTLIB) $(DCRYPT) $(DMALLOC) $(GMP)

mtm_mallory.o : mtm_mallory.c mtm.h edu.h
	$(CC) $(DEBUG) $(WFLAGS) -I. -I$(INCLUDES) -I$(DCRYPTINCLUDE)  -c mtm_mallory.c

mtm_mallory : mtm_mallory.o mtm_prot.o mtm_cert.o edu_misc.o
	$(CC) $(DEBUG) $(WFLAGS) -o $@ $@.o mtm_prot.o mtm_cert.o edu_misc.o -L. -L$(LIBS) -L$(DCRYPTLIB) $(DCRYPT) $(DMALLOC) $(GMP)

clean:
	-rm -f core *.core *.o *~ 

.PHONY: all clean
