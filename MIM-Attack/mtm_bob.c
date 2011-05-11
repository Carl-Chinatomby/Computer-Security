#include "mtm.h"

void 
usage (const char *pname)
{
  fprintf (stderr, "Simple Diffie-Hellman-like Key Exchange: Responder\n");
  fprintf (stderr, "Usage: %s [-p CA-PUB-FILE] SK-FILE CERT-FILE OUT-FD\n", pname);
  exit (1);
}

int
main (int argc, char **argv)
{
  char *ke_msg1 = NULL;
  const char *ke_msg2 = NULL;
  char *ca_file = NULL;
  char *sk_file = NULL;
  char *cert_file = NULL;
  int out_fd;
  flow1 *from_a = NULL;
  flow2 *to_a = NULL;
  cert *own_cert = NULL;
  dckey *sk = NULL;
  dckey *ca_pk = NULL;
  u_char seskey[sha1_hashsize];
  char *secret = NULL;

  if ((argc == 4) && argv[1][0] != '-') {
    /* no -p option */
    ca_file = "./.pki/ca.pub";
  }
  else if ((argc == 5)
	   && (argv[1][0] != '-') 
	   && (argv[1] + 1) && (argv[1][1] != 'p')
	   && (argv[1] + 2)) {
    /* -p option present, followed by CERT-FILE without separating blank  */
    ca_file = argv[1] + 2;
  }
  else if ((argc == 6) && !strcmp (argv[1], "-p")) {
    /* -p option present, followed by blank and CERT-FILE */
    ca_file = argv[2];
  }
  else {
    usage (argv[0]);
    /* does not return */
  }

  setprogname (argv[0]);
  ri ();

  sk_file = argv[argc - 3];
  cert_file = argv[argc - 2];
  out_fd = atoi (argv[argc - 1]);

  if (!cert_verify (own_cert = cert_read (cert_file))) {
      fprintf (stderr, "%s: trouble reading certificate from %s, or certificate expired\n",
	      getprogname (), cert_file);
      perror (getprogname ());

      exit (1);
  }
  else {
    ca_pk = pk_from_file (ca_file);
    if (!(ke_msg1 = read_line (0))
	|| !(from_a = process_ke_msg (ke_msg1, ca_pk))) {
      fprintf (stderr, "error reading/parsing alice's message:\n%s", ke_msg1);
      dcfree (ca_pk);
      ca_pk = NULL;
      check_n_free (&ke_msg1);

      exit (1);
    }
    dcfree (ca_pk);
    ca_pk = NULL;
    check_n_free (&ke_msg1);

    to_a = prepare_ke_reply (own_cert, from_a);
    sk = sk_from_file (sk_file);
    ke_msg2 = export_ke_reply (from_a, to_a, sk);
    dcfree (sk);
    sk = NULL;
    write_chunk (1, ke_msg2, strlen (ke_msg2));
    check_n_free ((char **) &ke_msg2);

    /* derive_key looks at seskey to know if it the caller is alice or bob */
    strncpy ((char *) seskey, "bob", aes_blocklen);
    if (derive_key (seskey, from_a, to_a) == -1) {
      fprintf (stderr, "error deriving session key for bob.\n");
      flow1_clr (from_a);
      flow2_clr (to_a);
      
      exit (1);
    }
    else {
       fprintf(stderr, "B: My session key is: %s\n", seskey);
      secret = get_secret (seskey);

      /* dump the chosen secret to the launcher */
      if ((write_chunk (out_fd, secret, strlen (secret)) == -1) 
	  || (write_chunk (out_fd, "\n", 1) == -1)) {
	fprintf (stderr, "error writing to the launcher.\n");
	bzero (seskey, sha1_hashsize);
	bzero (secret, strlen (secret));
	xfree (secret);
	secret = NULL;
	flow1_clr (from_a);
	flow2_clr (to_a);
	
	exit (1);
      }
      bzero (seskey, sha1_hashsize);
      bzero (secret, strlen (secret));
      xfree (secret);
      secret = NULL;
      flow1_clr (from_a);
      flow2_clr (to_a);
    }
  }

  /* fprintf (stderr, "bob:done.\n"); */
  return 0;
}
