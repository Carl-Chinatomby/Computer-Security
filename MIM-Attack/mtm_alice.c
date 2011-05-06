#include "mtm.h"

void 
usage (const char *pname)
{
  fprintf (stderr, "Simple Diffie-Hellman-like Key Exchange: Initiator\n");
  fprintf (stderr, "Usage: %s [-p CA-PUB-FILE] SK-FILE CERT-FILE RESPONDER-ID OUT-FD\n", pname);
  exit (1);
}

int
main (int argc, char **argv)
{
  const char *ke_msg1 = NULL;
  char *ke_msg2 = NULL;
  char *ca_file = NULL;
  char *sk_file = NULL;
  char *cert_file = NULL;
  char *resp_id = NULL;
  int out_fd;
  flow1 *to_b = NULL;
  flow2 *from_b = NULL;
  cert *own_cert = NULL;
  dckey *sk = NULL;
  dckey *ca_pk = NULL;
  u_char seskey[sha1_hashsize], secret[aes_blocklen];
  char *pretty_secret = NULL;

  if ((argc == 5) && argv[1][0] != '-') {
    /* no -p option */
    ca_file = "./.pki/ca.pub";
  }
  else if ((argc == 6)
	   && (argv[1][0] != '-') 
	   && (argv[1] + 1) && (argv[1][1] != 'p')
	   && (argv[1] + 2)) {
    /* -p option present, followed by CERT-FILE without separating blank  */
    ca_file = argv[1] + 2;
  }
  else if ((argc == 7) && !strcmp (argv[1], "-p")) {
    /* -p option present, followed by blank and CERT-FILE */
    ca_file = argv[2];
  }
  else {
    usage (argv[0]);
    /* does not return */
  }

  setprogname (argv[0]);
  ri ();

  sk_file = argv[argc - 4];
  cert_file = argv[argc - 3];
  resp_id = argv[argc - 2];
  out_fd = atoi (argv[argc - 1]);

  if (!cert_verify (own_cert = cert_read (cert_file))) {
      fprintf (stderr, "%s: trouble reading certificate from %s, or certificate expired\n",
	      getprogname (), cert_file);
      perror (getprogname ());

      exit (1);
  }
  else {
    to_b = prepare_ke_msg (own_cert, xstrdup (resp_id));
    sk = sk_from_file (sk_file);
    ke_msg1 = export_ke_msg (to_b, sk);
    dcfree (sk);
    sk = NULL;
    write_chunk (1, ke_msg1, strlen (ke_msg1));
    check_n_free ((char **) &ke_msg1);
    ca_pk = pk_from_file (ca_file);
    if (!(ke_msg2 = read_line (0)) 
	|| !(from_b = process_ke_reply (to_b, ke_msg2, ca_pk))) {
      fprintf (stderr, "error reading/parsing bob's message:\n%s", ke_msg2);
      dcfree (ca_pk);
      ca_pk = NULL;
      check_n_free(&ke_msg2);
      
      exit (1);
    }

    dcfree (ca_pk);
    ca_pk = NULL;
    check_n_free(&ke_msg2);

    /* derive_key looks at seskey to know if it the caller is alice or bob */
    seskey[0] = 'a';
    if (derive_key (seskey, to_b, from_b) == -1) {
      fprintf (stderr, "error deriving session key for alice.\n");
      flow1_clr (to_b);
      flow2_clr (from_b);
      
      exit (1);
    }
    else {
      /* choose a random number to send */
      prng_getbytes (secret, aes_blocklen);
      cat_buf (&pretty_secret, secret, aes_blocklen);
      
      /* send it to bob, encrypted under the newly established session key */
      send_secret (1, secret, seskey);

      /* dump the chosen secret to standard error */
      if ((write_chunk (out_fd, pretty_secret, strlen (pretty_secret)) == -1)
	  || (write_chunk (out_fd, "\n", 1) == -1)) {
	fprintf (stderr, "error writing to the launcher.\n");
	bzero (seskey, sha1_hashsize);
	bzero (secret, sizeof (secret));
	bzero (pretty_secret, strlen (pretty_secret));
	xfree (pretty_secret);
	pretty_secret = NULL;
	flow1_clr (to_b);
	flow2_clr (from_b);
	
	exit (1);
      }

      /* wipe out sensitive data */
      bzero (seskey, sha1_hashsize);
      bzero (secret, sizeof (secret));
      bzero (pretty_secret, strlen (pretty_secret));
      xfree (pretty_secret);
      pretty_secret = NULL;
      flow1_clr (to_b);
      flow2_clr (from_b);
    }
  }

  /* fprintf (stderr, "alice:done.\n"); */
  return 0;
}
