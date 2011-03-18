#ifndef _EDU_H_
#define _EDU_H_

#include "dcrypt.h"

/* edu_misc.c */
void ri (void);
char *import_from_file (int fpk);
dckey *import_pub_from_file (int fdpk);
dckey *import_priv_from_file (int fdpk);
dckey *sk_from_file (const char *fn);
dckey *pk_from_file (const char *fn);
void write_pkfile (const char *pkfname, dckey *sk);
void write_skfile (const char *skfname, dckey *sk);
int write_chunk (int fd, const char *buf, u_int len);
int cat_buf (char **dstp, const void *buf, size_t len);

#define check_n_free(a)  if ((a) && (*(a))) {\
 xfree (*(a)); (*(a)) = NULL;}

#ifndef HAVE_GETPROGNAME
# define MY_MAXNAME 80
extern char *my_progname;
const char *getprogname(void);
void setprogname(const char *n);
#endif /* HAVE_GETPROGNAME */

struct house_keeping {
  const char *fname;
  dckey **p_key;
  int *p_fout;
  int *p_fin;
  char **p_buf0;
  char **p_buf1;
  char **p_buf2;
  char **p_hsha;
  sha1_ctx **p_sha_key;
  char **p_ctxt_hd;
  aes_ctx *p_aes_key;
  char **p_raw_keys; 
};
typedef struct house_keeping house_keeping;

enum hkeep_status {hkeep_ok = 0, hkeep_err, hkeep_trunc};
typedef enum hkeep_status hkeep_status;

void  hkeep_init (house_keeping *p_hk, 
		  const char *fname, dckey **p_key, int *p_fout, int *p_fin,
		  char **p_buf0, char **p_buf1, char **p_buf2, char **p_hsha, 
		  sha1_ctx **p_sha_key, char **p_ctxt_hd, aes_ctx *p_aes_key,
		  char **p_raw_keys);

void hkeep_cleanup (house_keeping *p_hk, hkeep_status st);

/* edu_keygen.c */

#define CCA_STRENGTH 16 /* must be one of 16, 24 or 32; used to set AES keys */

#endif /* _EDU_H_ */
