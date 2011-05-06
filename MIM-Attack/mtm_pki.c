#include "mtm.h"

void 
usage (const char *pname)
{
  fprintf (stderr, "Simple Certificate Generation Utility\n");
  fprintf (stderr, "Usages: 1) %s init\n", pname);
  fprintf (stderr, "           Initializes the certification mechanism.\n\n");
  fprintf (stderr, "           A new private key/public key pair is generated and\n");
  fprintf (stderr, "           stored in the files ($PWD)/.pki/ca.{priv,pub}\n");
  fprintf (stderr, "           (The directory ($PWD)/.pki/ is created if it didn't exist.)\n\n");
  fprintf (stderr, "        2) %s cert [-g SK-FILE] [-o CERT-FILE] [-e DAYS] PK-FILE ID\n", pname);
  fprintf (stderr, "           Creates a certificate under the CA located at ($PWD)/.pki.\n\n");
  fprintf (stderr, "           Exits if ($PWD)/.pki/ or ($PWD)/.pki/ca.priv do not exist\n");
  fprintf (stderr, "           Otherwise, signs a certificate binding ID to the public key\n");
  fprintf (stderr, "           contained in PK-FILE.\n");
  fprintf (stderr, "           (Notice that ID cannot contain the ',' (comma) character.)\n");
  fprintf (stderr, "           If the option -g (generate) is specified, a new key pair is\n");
  fprintf (stderr, "           generated, and stored in SK-FILE and PK-FILE.\n"); 
  fprintf (stderr, "           By default, the certificate is valid for 30 days, and it is\n");  
  fprintf (stderr, "           stored in a file named ID.cert, unless the -o option is used.\n");
  fprintf (stderr, "           (In both cases, previous content is lost if output file existed.)\n");
  fprintf (stderr, "           The -e option can be used to set the duration (in days) of the\n");
  fprintf (stderr, "           validity period.  A value of 0 means \"never expires\";\n"); 
  fprintf (stderr, "           otherwise, the maximum duration is 4 years = 1461 days.\n"); 
  fprintf (stderr, "           (Greater values result in no certificate being created.)\n\n");  
  fprintf (stderr, "        3) %s check CERT-FILE PK-FILE ID\n", pname);
  fprintf (stderr, "           Checks that the certificate stored in CERT-FILE was properly\n");
  fprintf (stderr, "           signed by the CA located at ($PWD)/.pki, that it has not expired,\n");
  fprintf (stderr, "           and that it corresponds to the identity ID and to the public key\n");
  fprintf (stderr, "           stored in PK-FILE.\n");
  fprintf (stderr, "           The result of the above checks is then printed to standard output.\n");

  exit (1);
}

dckey *
g_option (const char *sk_file)
{
  char *raw_pk = NULL;
  dckey *pk = NULL;
  dckey *sk = dckeygen (DC_RABIN, 1024, NULL); 
  write_skfile (sk_file, sk);
  
  if (!(raw_pk = dcexport_pub (sk)) 
      || ! (pk = dcimport_pub (raw_pk))) {
    fprintf (stderr, "%s: trouble exporting public key\n", getprogname ());
    check_n_free (&raw_pk);
    dcfree (sk);

    exit (1);
  }

  check_n_free (&raw_pk);
  return pk;
}

char *
o_option (const char *c_file)
{
  return xstrdup (c_file);
}

int
e_option (const char *days)
{
  int d = (days) ? asc_to_num (days, strlen (days)) : -1;
  
  return ((d >= 0) && (d <= 1461)) ? d : -1;
}

/* Creates the directory and files for the certificate mechanism */
void 
pki_init(void)
{
  int status;
  int fdca;
  dckey *ca = NULL;

  if ((((status = mkdir ("./.pki", 0700)) != -1) || (errno == EEXIST))
      && ((fdca = open ("./.pki/ca.priv",
			O_WRONLY|O_TRUNC|O_CREAT, 0600)) != -1)) {
    close (fdca);
    fdca = -1;
    /* key_type and nbits should be command-line options, but are
       just hard-coded for now */
    ca = dckeygen (DC_RABIN, 1024, NULL);
    /* now sk contains the newly created ca private key */
    write_skfile ("./.pki/ca.priv", ca);
    write_pkfile ("./.pki/ca.pub", ca);
  }
  else if (errno == EACCES) {
    perror (getprogname ());
    
    exit (1);
  }
  else 
    usage (getprogname ());
}

/* Verifies the validity of a certificate */
void 
pki_check(char *cert_file, char *pk_file, char *id)
{
  cert *c = cert_read (cert_file);
  dckey *pk = pk_from_file (pk_file);

  if (!c) {
    printf ("Error reading the certificate from %s\n", cert_file);
    
    exit (1);
  }

  if (!pk) {
    printf ("Error reading the public key from %s\n", pk_file);
    
    exit (1);
  }

  if (!cert_verify (c)) {
    printf ("Certificate invalid or expired\n");
    
    exit (1);
  }

  if (!dcareequiv (c->public_key, pk)) {
    printf ("The certificate in %s does not refer to the public key in %s\n",
	    cert_file, pk_file);
    
    exit (1);
  }
  
  if (strcmp (c->identity, id) != 0) {
    printf ("The certificate in %s does not refer to identity %s\n",
	    cert_file, id);
    
    exit (1);
  }

  /* everything checked out */
  printf ("Valid certificate\n");
  
  exit (0);
}

void
parse_options (dckey **ppk, char **pcfile, int *pdur, int argc, char **argv)
{
  char opt;
  char *opt_arg;
  int arg_idx = 2; 

  *ppk = NULL;
  *pcfile = NULL;
  *pdur = -1;

  while ((arg_idx < argc) && (argv[arg_idx][0] == '-')) {
    opt = argv[arg_idx][1];
    /* locate the argument to this option */
    opt_arg = (argv[arg_idx][2] != '\0')
      ? &(argv[arg_idx][2])
      : argv[++arg_idx];
    ++arg_idx;
    switch (opt) {
    case 'g':
      /* seen a -g option already? */
      if (*ppk) {
	  dcfree (*ppk);
	  usage (argv[0]);
	}
	else 
	  *ppk = g_option (opt_arg);
	break;
      case 'o':
	/* seen a -o option already? */
	if (*pcfile) {
	  if (*ppk) dcfree (*ppk);
	  usage (argv[0]);
	}
	else 
	  *pcfile = o_option (opt_arg);
	break;
      case 'e':
	/* seen a -e option already? */
	if (*pdur != -1) {
	  if (*ppk) dcfree (*ppk);
	  usage (argv[0]);
	}
	else
	  /* a -1 return value means "out of range"; display usage notice */
	  if ((*pdur = e_option (opt_arg)) == -1) usage (argv[0]);	  
	break;
      default:
	usage (argv[0]);
      }
    }      
    /* now we should have exactly two more args */ 
    if (arg_idx != argc - 2) 
      usage (argv[0]);
}

int 
main (int argc, char **argv)
{
  int fdca, fdpk;
  dckey *ca = NULL, *pk = NULL;
  char *id = NULL;
  char *cert_file = NULL, *pk_file = NULL;
  int duration = -1;

  ri ();

  if (argc < 2) 
    usage (argv[0]);
  else if (argc == 2) {
    if (strcmp (argv[1], "init") != 0)
      usage (argv[0]);
    else {
      setprogname (argv[0]);
      pki_init ();      
    }
  }
  else if (argc == 5) {
    if (strcmp (argv[1], "check") != 0)
      usage (argv[0]);
    else {
      setprogname (argv[0]);
      pki_check (argv[2], argv[3], argv[4]);      
    }
  }
  else if (strcmp (argv[1], "cert") != 0) {
    usage (argv[0]);
  }
  else {
    /* cert commnad */
    setprogname (argv[0]);

    /* first, let's take care of the options, if any */
    parse_options (&pk, &cert_file, &duration, argc, argv);

    /* the last two args are ID and PK-FILE */
    pk_file = argv[argc - 2];
    id = argv[argc - 1];
    /* set up default values for parameters not affected by the options */
    if (!cert_file) {
      /* default cert_file is ID.cert */
      if (cat_str (&cert_file, id)
	  || cat_str (&cert_file, ".cert")) {
	xfree (cert_file);
	exit (1);	    
      }
    }
      
    if (duration == -1) 
      /* default duration is 30 days */
      duration = 30;

    /* take care of the public key that we are certifying */
    /* if the -g option was used, we have to write the pk to pk_file */
    if (pk) 
      write_pkfile (pk_file, pk); 
    /* otherwise, import pk from pk_file */
    else {
      if ((fdpk = open (pk_file, O_RDONLY)) == -1) {
	if (errno == ENOENT) {
	  usage (argv[0]);
	}
	else {
	  perror (argv[0]);
	  
	  exit (1);
	}
      }
      else if (!(pk = import_pub_from_file (fdpk))) {
	fprintf (stderr, "%s: no public key found in %s\n", argv[0], pk_file);
      
	close (fdpk);
	exit (1);
      }
      close (fdpk);
      fdpk = -1;
    }
    /* now read the ca private key from ./.pki/ca.priv */
    if ((fdca = open ("./.pki/ca.priv", O_RDONLY)) == -1) {
      if (errno == ENOENT) {
	usage (argv[0]);
      }
      else {
	perror (argv[0]);
	
	exit (1);
      }
    }   
    else {
      if (!(ca = import_priv_from_file (fdca))) {
	fprintf (stderr, "%s: no private key found in %s\n", 
		argv[0], "./.pki/ca.priv");
	
	close (fdca);
	exit (1);
      }
      close (fdca);
      fdca = -1;

      /* prepare a cert, sign it and write it to cert_file */
      switch (cert_sign_n_write (ca, id, pk, duration, cert_file)) {
      case 0:
	/* no error */
	/* the ca signing key is not needed anymore: wipe it out */
	dcfree (ca);
	ca = NULL;
	break;
      case -1:
	/* trouble with the write system call */
	check_n_free (&cert_file);
	dcfree (ca);
	exit (1);
      case -2:
	/* trouble preparing/signinig the certificate */
	check_n_free (&cert_file);
	dcfree (ca);
	exit (1);
      default:
	check_n_free (&cert_file);
	dcfree (ca);
	exit (1);
      }

      assert (cert_verify (cert_read (cert_file)));
      
      dcfree (pk);
      pk = NULL;
    }
  }
  check_n_free (&cert_file);
  
  return 0;
}
