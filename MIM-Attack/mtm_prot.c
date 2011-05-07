#include "mtm.h"

/* read from fd until it gets a '\n' */
char *
read_line (int fd)
{
  int n_read = 0, n_tot = 0, chunk = 512;
  char *res = xmalloc (chunk + 1);  /* extra byte to hold '\0' */
  do {
    if ((n_read = read (fd, res + n_tot, chunk - n_read)) == -1) {
      perror (getprogname ());
      
      exit (1);
    }
    else if (n_read == 0) {
      fprintf (stderr, "Unexpected end of file\n");
      check_n_free (&res);
      return NULL;
    }
    else {
      n_tot += n_read;
      /* we need to NULL-terminate res to use strchr in the exit test */
      res[n_tot] = '\0';
      if (n_tot && ((n_tot % chunk) == 0)) {
	chunk *= 2;
	res = xrealloc (res, n_tot + chunk + 1);
      }
    }
  } while (!strchr (res, '\n'));

  return res;
}

flow1 *
prepare_ke_msg (const cert *c_a, const char *b)
{
  flow1 *res = xmalloc (sizeof (flow1));
  const char *param = eg_getparam_default (1024);
  char raw_n_a[sha1_hashsize];

  /* dummy initialization */
  mpz_init (res->p);
  mpz_init (res->q);
  mpz_init (res->g);
  mpz_init (res->elem_a);
  res->n_a = res->id_b = NULL;
  res->c_a = NULL;
  res->sig_a = NULL;
  
  res->version = xstrdup (FLOW1_VER);
  if (!param || skip_str (&param, "p=")
      || read_mpz (&param, res->p)
      || skip_str (&param, ",q=")
      || read_mpz (&param, res->q)
      || skip_str (&param, ",g=")
      || read_mpz (&param, res->g)) {
    xfree (res);

    return NULL;
  }

  mpz_init (res->elem_a);  
  prng_getfrom_zn (res->elem_a, res->q);

  prng_getbytes (raw_n_a, sha1_hashsize);
  res->n_a = armor64(raw_n_a, sha1_hashsize); 
  res->id_b = xstrdup (b);
  res->c_a = cert_dup (c_a);

  return res;
}

const char *
export_ke_msg (flow1 *f, const dckey *sk)
{
  char *res = NULL;
  char *cert_a = NULL;
  mpz_t y_a;

  mpz_init (y_a);
  mpz_powm (y_a, f->g, f->elem_a, f->p);
  if (!f || cat_str (&res, f->version)
      || cat_str (&res, ":param=(p=")
      || cat_mpz (&res, f->p)
      || cat_str (&res, ",q=")
      || cat_mpz (&res, f->q)
      || cat_str (&res, ",g=")
      || cat_mpz (&res, f->g)
      || cat_str (&res, "),n_a=")
      || cat_str (&res, f->n_a)
      || cat_str (&res, ",id_b=")
      || cat_str (&res, f->id_b)
      || (sk && !(f->sig_a = dcsign (sk, res)))
      || cat_str (&res, ",y_a=")
      || cat_mpz (&res, y_a)
      || cat_str (&res, ",cert_a=(")
      || !(f->c_a)
      || !(cert_a = cert_export (f->c_a, 1))
      || cat_str (&res, cert_a)
      || (!f->sig_a)
      /* overwrite tailing '\n' with ')' */
      || (res[strlen(res) - 1] = ')', cat_str (&res, ",sig_a="))
      || cat_str (&res, f->sig_a)
      || cat_str (&res, "\n")) {
    check_n_free (&res);
    
    res = NULL;
  }
  check_n_free (&cert_a);
  mpz_clear (y_a);

  return res;
}

flow1 *
process_ke_msg (const char *msg, const dckey *ca_pk)
{
  flow1 *res = NULL;
  char *signed_part;
  size_t signed_len = 0;
  const char *signed_part_begin = NULL;
  const char *saved = NULL;
  const char *q = NULL;
  char *p = NULL;
  
  /* dummy initialization */
  res = (flow1 *) xmalloc (sizeof (flow1));
  res->version = NULL;
  mpz_init (res->p);
  mpz_init (res->q);
  mpz_init (res->g);
  mpz_init (res->elem_a);
  res->n_a = res->id_b = NULL;
  res->c_a = NULL;
  res->sig_a = NULL;

  /* parse msg */

  /* keep track of the beginning of the string as this is what was signed */
  signed_part_begin = msg;

  /* first find the version string and the group parameters */ 
  if (skip_str (&msg, FLOW1_VER)
      || skip_str (&msg, ":param=(p=")
      || read_mpz (&msg, res->p)
      || skip_str (&msg, ",q=")
      || read_mpz (&msg, res->q)
      || skip_str (&msg, ",g=")
      || read_mpz (&msg, res->g)
      || skip_str (&msg, "),n_a=")) {
    flow1_clr (res);
    return NULL;
  }
  res->version = xstrdup (FLOW1_VER);
  
  /* copy in n_a */
  saved = msg;
  if (!(msg = strchr (msg, ',')) || skip_str (&msg, ",id_b=")) {
    flow1_clr (res);
    return  NULL;
  }
  /* copy the portion from saved to msg - 7 */
  res->n_a = (char *)xmalloc (msg - 7 - saved + 2); /* extra byte for '\0' */
  strncpy (res->n_a, saved, msg - 7 - saved + 1);
  (res->n_a)[msg - 7 - saved + 1] = '\0'; 
  
  /* copy in id_b */
  saved = msg;
  if (!(msg = strchr (msg, ',')) || skip_str (&msg, ",y_a=")) {
    flow1_clr (res);
    return  NULL;
  }
  /* copy the portion from saved to msg - 6 */
  res->id_b = (char *)xmalloc (msg - 6 - saved + 2); /* extra byte for '\0' */
  strncpy (res->id_b, saved, msg - 6 - saved + 1);
  (res->id_b)[msg - 6 - saved + 1] = '\0'; 
  
   /* The part of the messaged that Alice signed in this broken version of
     the protocol ends here */
  signed_len = msg - 5 - signed_part_begin;
  /* copy the message so far (excluding the trailing ',') into signed_part */
  signed_part = (char *) xmalloc (signed_len + 1);
  strncpy(signed_part, signed_part_begin, signed_len);
  signed_part [signed_len] = '\0';

  /* get the value of y_a */
  if (read_mpz (&msg, res->elem_a) || skip_str (&msg, ",cert_a=(")) {
    flow1_clr (res);
    return  NULL;
  }

  /* now find the certificate, which is terminated by "),sig_a=" */
  saved = msg;
  if (!(msg = strstr (msg, "),sig_a="))) {
    flow1_clr (res);
    return  NULL;
  }
  /* skip "),sig_a=" */
  msg += 8;
  /* copy the portion from saved to msg - 8 into a temporary buffer */
  p = (char *) xmalloc (msg - 8 - saved + 2);
  strncpy (p, saved, msg - 8 - saved + 1);
  p[msg - 8 - saved + 1] = '\0'; 
  /* import the certificate from this buffer */
  if (!(res->c_a = cert_import (p))) {
    xfree (p);
    flow1_clr (res);
    return  NULL;
  }
  xfree (p);
  p = NULL;

  /* the rest of the msg should just be the signature, ended by a '\n' */
  if (*(q = msg + strlen (msg) - 1) != '\n') {
    flow1_clr (res);
    return  NULL;
  }
  /* copy this (up to and not including the trailing '\n') into res->sig_a */
  res->sig_a = (char *) xmalloc (q - msg + 1);
  strncpy(res->sig_a, msg, q - msg);
  res->sig_a[q - msg] = '\0';

  /* now check that:
   * - we are using the same CA (if ca_pk was specified)
   * - that the certificate is good
   * - that the signature is valid
   */
  if ((ca_pk && !dcareequiv (ca_pk, res->c_a->issuer))
      || !cert_verify (res->c_a)
      || (dcverify (res->c_a->public_key, signed_part, res->sig_a) == -1)) {
    flow1_clr (res);
    res = NULL;
  }

  check_n_free (&signed_part);
  return res;
}

flow2 *
prepare_ke_reply (const cert *c_b, const flow1 *f)
{
  flow2 *res = xmalloc (sizeof (flow2));
  char raw_n_b[sha1_hashsize];

  res->version = xstrdup (FLOW2_VER);

  mpz_init (res->elem_b);
  prng_getfrom_zn (res->elem_b, f->q);

  res->n_a = xstrdup (f->n_a); 
  prng_getbytes (raw_n_b, sha1_hashsize);
  res->n_b = armor64(raw_n_b, sha1_hashsize); 
  res->id_a = xstrdup (f->c_a->identity);
  res->c_b = cert_dup (c_b);
  res->sig_b = NULL;

  return res;
}

const char *
export_ke_reply (const flow1 *par, flow2 *f, const dckey *sk)
{
  char *res = NULL;
  char *cert_b = NULL;
  mpz_t y_b;

  mpz_init (y_b);
  mpz_powm (y_b, par->g, f->elem_b, par->p);

  if (!f || cat_str (&res, f->version)
      || cat_str (&res, ":n_a=")
      || cat_str (&res, f->n_a)
      || cat_str (&res, ",n_b=")
      || cat_str (&res, f->n_b)
      || cat_str (&res, ",id_a=")
      || cat_str (&res, f->id_a)
      || (sk && !(f->sig_b = dcsign (sk, res)))
      || cat_str (&res, ",y_b=")
      || cat_mpz (&res, y_b)
      || cat_str (&res, ",cert_b=(")
      || !(f->c_b)
      || !(cert_b = cert_export (f->c_b, 1)) /* include the sig in the cert */
      || cat_str (&res, cert_b)
      || (!f->sig_b)
      /* overwrite tailing '\n' with ')' */
      || (res[strlen(res) - 1] = ')', cat_str (&res, ",sig_b="))
      || cat_str (&res, f->sig_b)
      || cat_str (&res, "\n")) {
    check_n_free (&res);

    res = NULL;
  }
  check_n_free (&cert_b);
  mpz_clear (y_b);

  return res;
}

flow2 *
process_ke_reply (const flow1 *own, const char *reply, const dckey *ca_pk)
{
  flow2 *res = NULL;
  char *signed_part;
  size_t signed_len = 0;
  const char *signed_part_begin = NULL;
  const char *saved = NULL;
  const char *q = NULL;
  char *p = NULL;
  
  /* dummy initialization */
  res = (flow2 *) xmalloc (sizeof (flow2));
  mpz_init (res->elem_b);
  res->version = NULL;
  res->n_a = res->n_b = res->id_a = NULL;
  res->c_b = NULL;
  res->sig_b = NULL;
  
  /* parse reply */

  /* keep track of the beginning of the string as this is what was signed */
  signed_part_begin = reply;

  /* first find the version string and n_a */ 
  if (skip_str (&reply, FLOW2_VER)
      || skip_str (&reply, ":n_a=")) {
    flow2_clr (res);
    return NULL;
  }
  res->version = xstrdup (FLOW2_VER);
  
  /* copy in n_a */
  saved = reply;
  if (!(reply = strchr (reply, ',')) || skip_str (&reply, ",n_b=")) {
    flow2_clr (res);
    return  NULL;
  }
  /* copy the portion from saved to reply - 6 */
  res->n_a = (char *)xmalloc (reply - 6 - saved + 2); /* extra byte for '\0' */
  strncpy (res->n_a, saved, reply - 6 - saved + 1);
  (res->n_a)[reply - 6 - saved + 1] = '\0'; 
  
  /* copy in n_b */
  saved = reply;
  if (!(reply = strchr (reply, ',')) || skip_str (&reply, ",id_a=")) {
    flow2_clr (res);
    return  NULL;
  }
  /* copy the portion from saved to reply - 7 */
  res->n_b = (char *)xmalloc (reply - 7 - saved + 2); /* extra byte for '\0' */
  strncpy (res->n_b, saved, reply - 7 - saved + 1);
  (res->n_b)[reply - 7 - saved + 1] = '\0'; 
  
  /* copy in id_a */
  saved = reply;
  if (!(reply = strchr (reply, ',')) || skip_str (&reply, ",y_b=")) {
    flow2_clr (res);
    return  NULL;
  }
  /* copy the portion from saved to reply - 6 */
  res->id_a = (char *)xmalloc (reply - 6 - saved + 2); /* extra byte for '\0'*/
  strncpy (res->id_a, saved, reply - 6 - saved + 1);
  (res->id_a)[reply - 6 - saved + 1] = '\0'; 
  
  /* The part of the messaged that Bob signed in this broken version of
     the protocol ends here */
  signed_len = reply - 5 - signed_part_begin;
  /* copy the message so far (excluding the trailing ',') into signed_part */
  signed_part = (char *) xmalloc (signed_len + 1);
  strncpy(signed_part, signed_part_begin, signed_len);
  signed_part [signed_len] = '\0';

  /* get the value of y_b */
  if (read_mpz (&reply, res->elem_b) || skip_str (&reply, ",cert_b=(")) {
    flow2_clr (res);
    return  NULL;
  }

  /* now find the certificate, which is terminated by "),sig_b=" */
  saved = reply;
  if (!(reply = strstr (reply, "),sig_b="))) {
    flow2_clr (res);
    return  NULL;
  }
  /* skip "),sig_b=" */
  reply += 8;
  /* copy the portion from saved to reply - 8 into a temporary buffer */
  p = (char *) xmalloc (reply - 8 - saved + 2);
  strncpy (p, saved, reply - 8 - saved + 1);
  p[reply - 8 - saved + 1] = '\0'; 
  /* import the certificate from this buffer */
  if (!(res->c_b = cert_import (p))) {
    xfree (p);
    flow2_clr (res);
    return  NULL;
  }
  xfree (p);
  p = NULL;

  /* the rest of the reply should just be the signature, ended by a '\n' */
  if (*(q = reply + strlen (reply) - 1) != '\n') {
    flow2_clr (res);
    return  NULL;
  }
  /* copy this (up to and not including the trailing '\n') into sig_b */
  res->sig_b = (char *) xmalloc (q - reply + 1);
  strncpy(res->sig_b, reply, q - reply);
  res->sig_b[q - reply] = '\0';

  /* now check that:
   * - we are using the same CA (if ca_pk was specified)
   * - that the certificate is good and it is for id_b
   * - that the signature is valid
   * - that the message mention the correct nonce n_a and identity id_a
   */
  if ((ca_pk && !dcareequiv (ca_pk, res->c_b->issuer))
      || !cert_verify (res->c_b) || strcmp (own->id_b, res->c_b->identity)
      || (dcverify (res->c_b->public_key, signed_part, res->sig_b) == -1)
      || strcmp (own->n_a, res->n_a) 
      || strcmp (own->c_a->identity, res->id_a)) {
    flow2_clr (res);
    res = NULL;
  }
 
  check_n_free (&signed_part);
  return res;
}

int 
derive_key (u_char out[sha1_hashsize], const flow1 *a, const flow2 *b)
{
  char who = *((char *)out);
  sha1_ctx sc;
  mpz_t k;
  char *raw_k = NULL;
  mpz_init (k);

  /* out is used to specify whether a->elem_a or b->elem_b is the exponent */
  if (who == 'a')
    mpz_powm (k, b->elem_b, a->elem_a, a->p);
  else if (who == 'b')
    mpz_powm (k, a->elem_a, b->elem_b, a->p);
  else return -1;

  if (cat_mpz (&raw_k, k)) {
    mpz_clear (k);
    return -1;
  }
  
  sha1_init (&sc);
  sha1_update (&sc, raw_k, strlen (raw_k));
  sha1_update (&sc, a->n_a, strlen (a->n_a));
  sha1_update (&sc, b->n_b, strlen (b->n_b));
  sha1_final (&sc, out);

  xfree (raw_k);
  return 0;
}

void
send_secret (int fd, u_char secret[aes_blocklen], 
	     const u_char seskey[sha1_hashsize])
{
  char *armored_secret = NULL;
  aes_ctx aes;

  /* encrypt secret with the session key just generated */
  aes_setkey (&aes, seskey, 16);   /* only use the first 16 bytes of seskey */ 
  aes_encrypt (&aes, secret, secret);
  aes_clrkey (&aes);

      fprintf(stderr, "before armored secret is %s", secret);
   
  /* armor the ciphertext and send it to bob */
  armored_secret = armor64 (secret, aes_blocklen);

  write_chunk (fd, armored_secret, strlen (armored_secret));
  write (fd, "\n", 1);
  xfree (armored_secret);
}

char *
get_secret (const u_char seskey[sha1_hashsize])
{
  char secret[aes_blocklen];
  char *pretty_secret = NULL;
  aes_ctx aes;
  char *armored = read_line (0);
  char *last = strchr (armored, '\n');

  if (!last) 
    return NULL;
  *last = '\0';

  aes_setkey (&aes, seskey, 16);   /* only uses the first 16 bytes of seskey */ 

  /* dearmor and decrypt the ciphertext */
  dearmor64 (secret, armored);
  aes_decrypt (&aes, secret, secret);
  aes_clrkey (&aes);
  cat_buf (&pretty_secret, secret, aes_blocklen);

  return pretty_secret;
}

