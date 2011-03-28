#include "edu.h"

void
write_pkfile (const char *pkfname, dckey *sk)
{
  int fdpk;
  char *p;
  int status;

  if (!(p = dcexport_pub (sk))) {
    printf ("%s: trouble exporting public part from a private key\n", 
	     getprogname ());
    
    dcfree (sk);

    exit (2);
  }
  else if ((fdpk = open (pkfname, O_WRONLY|O_TRUNC|O_CREAT, 0644)) == -1) {
    perror (getprogname ());
    free (p);
    dcfree (sk);

    exit (-1);
  }
  else {
    status = write (fdpk, p, strlen (p));
    if (status != -1) {
      status = write (fdpk, "\n", 1);
    }
    free (p);
    close (fdpk);
    /* do not dcfree sk under normal circumstances */ 

    if (status == -1) {
      printf ("%s: trouble writing public key to file %s\n", 
	       getprogname (), pkfname);
      perror (getprogname ());
      
      dcfree (sk);

      exit (-1);
    }
  }
}

void
write_skfile (const char *skfname, dckey *sk)
{
  int fdsk;
  char *s;
  int status;

  if (!(s = dcexport_priv (sk))) {
    printf ("%s: trouble exporting private key\n", getprogname ());
    
    dcfree (sk);

    exit (2);
  }
  else if ((fdsk = open (skfname, O_WRONLY|O_TRUNC|O_CREAT, 0600)) == -1) {
    perror (getprogname ());
    free (s);
    dcfree (sk);

    exit (-1);
  }
  else {
    status = write (fdsk, s, strlen (s));
    if (status != -1) {
      status = write (fdsk, "\n", 1);
    }
    free (s);
    close (fdsk);
    /* do not dcfree sk under normal circumstances */ 

    if (status == -1) {
      printf ("%s: trouble writing private key to file %s\n", 
	      getprogname (), skfname);
      perror (getprogname ());
      
      dcfree (sk);
      
      exit (-1);
    }
  }
}

void 
usage (const char *pname)
{
  printf ("Simple Key Pair Generation Utility\n");
  printf ("Usage: %s SK-FILE PK-FILE\n", pname);
  printf ("       If SK-FILE exists, writes the corresponding public key\n");
  printf ("       to PK-FILE.  Otherwise, generates a new private key/\n");
  printf ("       public key pair and writes them to SK-FILE and PK-FILE,\n");
  printf ("       respectively.  (Previous file content is lost.)\n");

  exit (1);
}

int 
main (int argc, char **argv)
{
  int fdsk;
  dckey *sk;
  char key_type[] = DC_RABIN;
  size_t nbits = 1024;

  if (argc != 3) {
    usage (argv[0]);
  }
  else {
    setprogname (argv[0]);

    if ((fdsk = open (argv[1], O_RDONLY, 0600)) == -1) { 
      if (errno == ENOENT) {
	/* just opened a new SK-FILE; let's create a new private key */
	/* key_type and nbits should be command-line options, but are
	   just hard-coded for now */
	ri ();

	sk = dckeygen (key_type, nbits, NULL);

	/* now sk contains the newly created private key */
	write_skfile (argv[1], sk);
	write_pkfile (argv[2], sk);
      }
      else {
	perror (argv[0]);

	exit (-1);
      }
    }
    else if (!(sk = import_priv_from_file (fdsk))) {
	printf ("%s: no private key found in %s\n", argv[0], argv[1]);

	close (fdsk);
	exit (2);
      }
      else {  /* SK-FILE exists and we could import a private key from it */
	close (fdsk);
	
	write_pkfile (argv[2], sk);
    }

    dcfree (sk);
  }

  return 0;
}

