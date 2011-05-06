#ifndef _MTM_H_
#define _MTM_H 1

#include "dcrypt.h"
#include "edu.h"

#include <stdio.h>
#include <stdlib.h>

#define CERT_VER "MTM-Cert-1"
#define FLOW1_VER "MTM-Flow1-1"
#define FLOW2_VER "MTM-Flow2-1"
#define SECS_PER_DAY (60 * 60 * 24)
#define EXP_CERT_GRACE (60 * 60) /* grace period (in secs) for expired certs */
struct cert {
  char *version;
  dckey *issuer;
  char *identity;
  dckey *public_key;
  time_t day_issued;
  time_t day_expires;
  char *sig;
};
typedef struct cert cert;

struct flow1 {
  char *version;
  mpz_t p, q, g;
  char *n_a, *id_b;
  mpz_t elem_a; /* = a for alice, = g^a mod p for bob */
  cert *c_a;
  char *sig_a;
};
typedef struct flow1 flow1;

#define flow1_clr(f) {\
  if (f) {\
    check_n_free(&((f)->version));\
    mpz_clear ((f)->p); mpz_clear ((f)->q); mpz_clear ((f)->g);\
    check_n_free (&((f)->n_a)); check_n_free (&((f)->id_b));\
    mpz_clear ((f)->elem_a);\
    if ((f)->c_a) {cert_clr ((f)->c_a); (f)->c_a = NULL;}\
    if ((f)->sig_a) {check_n_free (&((f)->sig_a));}\
    xfree (f);\
  }\
}

struct flow2 {
  char *version;
  char *n_a, *n_b, *id_a;
  mpz_t elem_b; /* = g^b mod p for alice, = b for bob */
  cert *c_b;
  char *sig_b;
};
typedef struct flow2 flow2;

#define flow2_clr(f) {\
  if (f) {\
    check_n_free(&((f)->version));\
    check_n_free (&((f)->n_a)); check_n_free (&((f)->n_b));\
    check_n_free (&((f)->id_a));\
    mpz_clear ((f)->elem_b);\
    if ((f)->c_b) {cert_clr ((f)->c_b); (f)->c_b = NULL;}\
    if ((f)->sig_b) {check_n_free (&((f)->sig_b));}\
    xfree (f);\
  }\
}



/* mtm_cert.c */

/* memory for pointers is allocated, so arguments can be freed on return */
cert *cert_init (const dckey *is, const char *id, const dckey *pk, 
		 unsigned int ndays);
cert *cert_dup (const cert *c);
char *cert_export (const cert *c, int with_sig);
int month_to_num (const char month[]);
int asc_to_num (const char *d, unsigned int l);
time_t parse_date (const char **a);
void cert_clr (cert *c);
cert *cert_import (const char *asc);
int cert_sign_n_write (const dckey *ca, const char *id, const dckey *pk, 
		       unsigned int ndays, const char *cert_file);
cert *cert_read (const char *cert_file);
int cert_verify (const cert *cert);

/* mtm_prot.c*/

char *read_line (int fd);
flow1 *prepare_ke_msg (const cert *c_a, const char *b);
const char *export_ke_msg (flow1 *f, const dckey *sk);
flow1 *process_ke_msg (const char *msg, const dckey *ca_pk);
flow2 *prepare_ke_reply (const cert *c_b, const flow1 *f);
const char *export_ke_reply (const flow1 *par, flow2 *f,
			     const dckey *sk);
flow2 *process_ke_reply (const flow1 *own, const char *reply,
			 const dckey *ca_pk);
int derive_key (u_char out[sha1_hashsize], const flow1 *a, const flow2 *b);
void send_secret (int fd, u_char out[aes_blocklen], 
		  const u_char seskey[sha1_hashsize]);
char *get_secret (const u_char seskey[sha1_hashsize]);

#endif /* !_MTM_H_ */
