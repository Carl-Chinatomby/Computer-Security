#include "edu.h"

#ifndef HAVE_GETPROGNAME
char *my_progname = NULL; 

const char *
getprogname(void) 
{
  return (my_progname ? my_progname : "");
}

void 
setprogname(const char *n) 
{
  int i, j;

  /* truncate n if longer than MY_MAXNAME chars */
  for (i = 0; (i < MY_MAXNAME) && n[i]; i++)
    ; /*intentionally empty */

  /* copy into my_progname as long as there is space ... */
  for (j = 0; (j < i) && (my_progname + j); j++)
    my_progname[j] = n [j];

  /* need more space? */
  if ((j < i) || !(my_progname [j])) {
    my_progname = (char *) xrealloc (my_progname, (i + 1)* sizeof (char));
    /* complete the copying */
    for (; j < i; j++) {
      assert (my_progname + j);
      my_progname[j] = n[j];
    }
  }

  assert (my_progname + j);
  my_progname[j] = '\0';
}  
#endif /* HAVE_GETPROGNAME */


void
ri (void)
{
  char *random_devs[] = {"/dev/urandom",
			 "/dev/random",
			 0};
  int i;
  int fd;
  int done = 0;

  /* first, check if one of /dev/random, /dev/urandom or /dev/prandom */   
  for (i = 0; (!done) && random_devs[i]; i++) {
    if ((fd = open (random_devs[i], O_RDONLY, 0600)) == -1) { 
      if (errno == ENOENT) {
	continue;      
      }
      else {
	fprintf (stderr, "%s: trouble reading from %s\n", 
		getprogname (), random_devs[i]);
	perror (getprogname ());
	
	exit (1);
      }
    }
    else {
      /* we found a random device; let's get some bytes from it */
      ssize_t seed_len = 2 * CCA_STRENGTH;
      char *seed = (char *) xmalloc (seed_len * sizeof (char));
      int cur_bytes_read, bytes_read = 0; 

      bytes_read = 0;
      do {
	cur_bytes_read = read (fd, seed, seed_len - bytes_read);
	bytes_read += cur_bytes_read;
      } while ((bytes_read < seed_len) && (cur_bytes_read > 0));
      if (bytes_read == seed_len) {
	prng_seed (seed, seed_len);
	done = 1;
      }
      else {
	fprintf (stderr, "%s: trouble reading from %s\n", 
		getprogname (), random_devs[i]);
	perror (getprogname ());
	
	exit (1);	
      }
      
      bzero (seed, seed_len);
      xfree (seed);
      seed = NULL;
    }
  }

  if (!done) {
    /* no /dev/?random device */
    /* quick'n dirty way to inialize the pseudorandom number generator */
    struct {
      int pid;
      int time;
    } rid;
    
    rid.pid = getpid ();
    rid.time = time (NULL);
    prng_seed (&rid, sizeof (rid));
    bzero (&rid, sizeof (rid));
  }
}

void
write_pkfile (const char *pkfname, dckey *sk)
{
  int fdpk;
  char *p;
  int status;

  if (!(p = dcexport_pub (sk))) {
    fprintf (stderr, "%s: trouble exporting public part from a private key\n", 
	     getprogname ());
    
    dcfree (sk);

    exit (1);
  }
  else if ((fdpk = open (pkfname, O_WRONLY|O_TRUNC|O_CREAT, 0644)) == -1) {
    perror (getprogname ());
    free (p);
    dcfree (sk);

    exit (1);
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
      fprintf (stderr, "%s: trouble writing public key to file %s\n", 
	       getprogname (), pkfname);
      perror (getprogname ());
      
      dcfree (sk);

      exit (1);
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
    fprintf (stderr, "%s: trouble exporting private key\n", getprogname ());
    
    dcfree (sk);

    exit (1);
  }
  else if ((fdsk = open (skfname, O_WRONLY|O_TRUNC|O_CREAT, 0600)) == -1) {
    perror (getprogname ());
    free (s);
    dcfree (sk);

    exit (1);
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
      fprintf (stderr, "%s: trouble writing private key to file %s\n", 
	      getprogname (), skfname);
      perror (getprogname ());
      
      dcfree (sk);
      
      exit (1);
    }
  }
}

char *
import_from_file (int fpk)
{
  /* XXX - reads the entire file into memory as a null-terminated string */
  /* XXX - big files could run it out of memory */
  size_t bufsize = 512; /* initial bufsize is enough for 1024-bit keys */
  size_t tot;           /* total bytes read so far */
  ssize_t cur;           /* no bytes read in the last read */
  char *buf = (char *) xmalloc (bufsize * sizeof (char));
  
  tot = 0;
  do {
    cur = read (fpk, buf + tot, bufsize - tot); 
    tot += cur;
    if (bufsize == tot) {/* saturated current size; double the buffer */
      bufsize <<= 1;
      buf = (char *) xrealloc (buf, bufsize);
    }
  } while (cur > 0);
  if (cur == -1) {
    fprintf (stderr, "%s: trouble importing key from file\n", 
	    getprogname ());
    perror (getprogname ());
    
    xfree (buf);
    close (fpk);
    
    exit (1); 
  } 
  else {
    assert (cur == 0);
    buf [tot] = '\0'; /* when we exit the reading loop, tot < bufsize */
  }

  return buf;
}

dckey *
import_pub_from_file (int fdpk)
{
  char *pretty_key = import_from_file (fdpk);
  dckey *key = dcimport_pub (pretty_key);

  xfree (pretty_key);
  close (fdpk);

  if (!key) {
    fprintf (stderr, "%s: trouble importing key from file\n",
	    getprogname ());
   
    exit (1);
  }


  return key;
}

dckey *
import_priv_from_file (int fdsk)
{
  char *pretty_key = import_from_file (fdsk);
  dckey *key = dcimport_priv (pretty_key);

  xfree (pretty_key);
  close (fdsk);

  if (!key) {
    fprintf (stderr, "%s: trouble importing key from file\n",
	    getprogname ());
   
    exit (1);
  }

  return key;
}

dckey *
sk_from_file (const char *fn)
{
  dckey *sk = NULL;
  int fdsk = open (fn, O_RDONLY); 

  if (fdsk == -1) {
    perror (getprogname ());
      
    exit (1);
  }
  else {
    if (!(sk = import_priv_from_file (fdsk))) {
      fprintf (stderr, "%s: no private key found in %s\n", getprogname (), fn);
      
      close (fdsk);
      exit (1);
    }
    close (fdsk);
  }
  
  return sk;
}

dckey *
pk_from_file (const char *fn)
{
  dckey *pk = NULL;
  int fdpk = open (fn, O_RDONLY); 
  
  if (fdpk == -1) {
    perror (getprogname ());
      
    exit (1);
  }
  else {
    if (!(pk = import_pub_from_file (fdpk))) {
      fprintf (stderr, "%s: no public key found in %s\n", getprogname (), fn);
      
      close (fdpk);
      exit (1);
    }
    close (fdpk);
  }
  
  return pk;
}

int 
write_chunk (int fd, const char *buf, u_int len) 
{
  int cur_bytes_written;
  u_int bytes_written = 0;

  while (bytes_written < len) {
    if ((cur_bytes_written = write (fd, buf + bytes_written,
					len - bytes_written)) != -1) {
	  bytes_written += cur_bytes_written;
    }
    else {
      return -1;
    }
  }

  return 0;
}

char
hex_nibble (u_char _nib) 
{
  u_char nib = (_nib & 0x0f);

  return ((nib < 10) ? ('0' + nib) : ('a' + nib - 10));
}

int
cat_buf (char **dstp, const void *buf, size_t len)
{
  const u_char *_buf = (const u_char *) buf;
  u_char *str = (u_char *) xmalloc (2 * len + 3);
  size_t i, j;
  int res;

  str[0] = '0';
  str[1] = 'x';
  for (i = 0, j = 2; i < len ; i++) {
    str[j++] = hex_nibble ((_buf[i] & 0xf0) >> 4);
    str[j++] = hex_nibble (_buf[i] & 0x0f);
  }

  str[j] = '\0';

  res = cat_str (dstp, str);
  xfree (str);
  return res;
}

void 
hkeep_init (house_keeping *p_hk, 
	    const char *fname, dckey **p_key, int *p_fout, int *p_fin,
	    char **p_buf0, char **p_buf1, char **p_buf2, char **p_hsha, 
	    sha1_ctx **p_sha_key, char **p_ctxt_hd, aes_ctx *p_aes_key,
	    char **p_raw_keys)
{
  p_hk->fname = fname;
  p_hk->p_key = p_key;
  p_hk->p_fout = p_fout;
  p_hk->p_fin = p_fin;
  p_hk->p_buf0 = p_buf0;
  p_hk->p_buf1 = p_buf1;
  p_hk->p_buf2 = p_buf2;
  p_hk->p_hsha = p_hsha;
  p_hk->p_sha_key = p_sha_key;
  p_hk->p_ctxt_hd = p_ctxt_hd;
  p_hk->p_aes_key = p_aes_key;
  p_hk->p_raw_keys = p_raw_keys;
}

void
hkeep_cleanup (house_keeping *p_hk, hkeep_status st)
{
  if (st != hkeep_ok) {
    perror (getprogname ());
    
    /* this cleaning is only needed if we are bailing out */
    if ((*p_hk->p_fout != -1) && (st == hkeep_trunc)) {
      /* the output file was created; truncate it to zero-length */
      close (*p_hk->p_fout); 
      *p_hk->p_fout = open (p_hk->fname, O_WRONLY|O_TRUNC, 0644);
      close (*p_hk->p_fout);
      *p_hk->p_fout = -1;
    }
    
    /* close the input fd */
    close (*p_hk->p_fin);
    *p_hk->p_fin = -1;
    
    /* clear the cryptographic keys */
    dcfree (*p_hk->p_key);
  }
  /* this cleaning is always needed */

  if (*p_hk->p_fout != -1) {
    close (*p_hk->p_fout); 
    *p_hk->p_fout = -1;
  }

  aes_clrkey (p_hk->p_aes_key);

  if (*p_hk->p_raw_keys) {
    bzero (*p_hk->p_raw_keys, strlen (*p_hk->p_raw_keys));
    check_n_free (p_hk->p_raw_keys);
  }
  
  /* free the rest */
  check_n_free (p_hk->p_hsha);

  check_n_free (p_hk->p_sha_key);
  
  check_n_free (p_hk->p_ctxt_hd);

  check_n_free (p_hk->p_buf0);
  
  check_n_free (p_hk->p_buf1);

  check_n_free (p_hk->p_buf2);
  
  if (st != hkeep_ok) {
    exit (1); 
  }
}
