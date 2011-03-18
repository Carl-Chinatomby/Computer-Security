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
    my_progname = (char *) realloc (my_progname, (i + 1)* sizeof (char));
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
	printf ("%s: trouble reading from %s\n", 
		getprogname (), random_devs[i]);
	perror (getprogname ());
	
	exit (-1);
      }
    }
    else {
      /* we found a random device; let's get some bytes from it */
      ssize_t seed_len = 2 * CCA_STRENGTH;
      char *seed = (char *) malloc (seed_len * sizeof (char));
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
	printf ("%s: trouble reading from %s\n", 
		getprogname (), random_devs[i]);
	perror (getprogname ());
	
	exit (-1);	
      }
      
      bzero (seed, seed_len);
      free (seed);
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

char *
import_from_file (int fpk)
{
  /* XXX - reads the entire file into memory as a null-terminated string */
  /* XXX - big files could run it out of memory */
  size_t bufsize = 512; /* initial bufsize is enough for 1024-bit keys */
  size_t tot;           /* total bytes read so far */
  ssize_t cur;           /* no bytes read in the last read */
  char *buf = (char *) malloc (bufsize * sizeof (char));
  
  tot = 0;
  do {
    cur = read (fpk, buf + tot, bufsize - tot); 
    tot += cur;
    if (bufsize == tot) {/* saturated current size; double the buffer */
      bufsize <<= 1;
      buf = (char *) realloc (buf, bufsize);
    }
  } while (cur > 0);
  if (cur == -1) {
    printf ("%s: trouble importing key from file\n", 
	    getprogname ());
    perror (getprogname ());
    
    free (buf);
    close (fpk);
    
    exit (-1); 
  } 
  else {
    assert (cur == 0);
    buf [tot + 1] = '\0'; /* when we exit the reading loop, tot < bufsize */
  }

  return buf;
}

dckey *
import_pub_from_file (int fdpk)
{
  char *pretty_key = import_from_file (fdpk);
  dckey *key = dcimport_pub (pretty_key);

  free (pretty_key);
  close (fdpk);

  if (!key) {
    printf ("%s: trouble importing key from file\n",
	    getprogname ());
   
    exit (2);
  }


  return key;
}

dckey *
import_priv_from_file (int fdsk)
{
  char *pretty_key = import_from_file (fdsk);
  dckey *key = dcimport_priv (pretty_key);

  free (pretty_key);
  close (fdsk);

  if (!key) {
    printf ("%s: trouble importing key from file\n",
	    getprogname ());
   
    exit (2);
  }

  return key;
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

#define check_n_free(a)  if ((a) && (*(a))) { free (*(a)); (*(a)) = NULL;}

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
    free (*p_hk->p_raw_keys);
    *p_hk->p_raw_keys = NULL;
  }
  
  /* free the rest */
  check_n_free (p_hk->p_hsha);

  check_n_free (p_hk->p_sha_key);
  
  check_n_free (p_hk->p_ctxt_hd);

  check_n_free (p_hk->p_buf0);
  
  check_n_free (p_hk->p_buf1);

  check_n_free (p_hk->p_buf2);
  
  if (st != hkeep_ok) {
    exit (-1); 
  }
}
