#include "mtm.h"

enum {FirstStage = 0, SecondStage, LastStage};

char intercepted_secret[aes_blocklen];
char *pretty_secret = NULL;

void 
usage (const char *pname)
{
  fprintf (stderr, "Simple Diffie-Hellman-like Key Exchange: Exploit\n");
  fprintf (stderr, "Usage: %s OUT_FD FROM_A TO_A FROM_B TO_B\n", pname);
  exit (1);
}

char *
attack (int s, const char *msg)
{
  /* use some static variable to keep state across the attack's stages */
   static char *state = NULL;
   static flow1 *from_a = NULL;
   static flow1 *m_from_a = NULL;
   flow2 *from_b = NULL;
   flow2 *m_from_b = NULL;
   char *payload = NULL;
   char *res = NULL;
   static mpz_t y_m;
   static mpz_t elem_m;
   static u_char am[sha1_hashsize];
   static u_char bm[sha1_hashsize];
   char *y_a_pos = NULL, *y_b_pos = NULL, *cert = NULL;
   char *altered_msg = NULL;  
   char *altered_msg2 = NULL;
   char *signed_port = NULL;
   size_t cpylen = 0;
   altered_msg = (char*) xmalloc((strlen(msg)+aes_blocklen) *sizeof(char));
     
   
  switch (s) {
  case FirstStage:
     from_a = process_ke_msg (msg, NULL);
     m_from_a = process_ke_msg(msg, NULL);
     state = NULL;
    
    /* build random number elem_m and then compute
     * y_m = g^m mod p 
    */
     mpz_init (y_m); 
     mpz_init (m_from_a->elem_a);
     prng_getfrom_zn(m_from_a->elem_a, from_a->q);
     mpz_powm (y_m, from_a->g, m_from_a->elem_a, from_a->p);
     
    /* let's build a new message with this new g^m mod p and everything 
     * else is copied */
     y_a_pos = strstr(msg, "y_a=");
     cpylen = y_a_pos - msg + 4;
     cert = strstr(msg, ",cert_a=");
     memcpy (altered_msg, msg, cpylen);
     altered_msg[cpylen] = '\0';
     cat_mpz(&altered_msg, y_m);
     cat_str(&altered_msg, cert);       
     res = xstrdup (altered_msg);
     break;
  case SecondStage:
     from_b = process_ke_reply (from_a, msg, NULL);
     state = NULL;
     altered_msg2 = (char*) xmalloc ((strlen(msg)+aes_blocklen) *sizeof(char));
    
     /* use the y_m from before to disrupt bob's message so alice can 
      * authenticate with mallory */
     y_b_pos = strstr(msg, "y_b=");
     cpylen = y_b_pos - msg + 4;
     memcpy (altered_msg, msg, cpylen);
     altered_msg[cpylen] = '\0';
     cat_mpz(&altered_msg, y_m); 
     cert = strstr(msg, ",cert_b=");
     cat_str(&altered_msg, cert);  
     
     /* we now have the necessary information to calculate
      * the session keys for y_am and y_bm */
     memcpy (altered_msg2, msg, cpylen);
     altered_msg2[cpylen] = '\0'; 
     cat_mpz(&altered_msg2, m_from_a->elem_a);
     cat_str(&altered_msg2, cert);
     m_from_b = process_ke_reply (from_a, altered_msg2, NULL);
     
     strncpy((char*) am, "bob", strlen("bob"));
     strncpy((char*) bm, "alice", strlen("alice")); 
     derive_key(am, from_a, m_from_b);     
     derive_key(bm, m_from_a, from_b);
     
     res = xstrdup (altered_msg); 
    
      break;
  case LastStage:
     payload = NULL; 
     state = NULL;
     u_char secret[aes_blocklen];
     
     aes_ctx aes;
     aes_setkey(&aes, am, 16); 
     dearmor64(secret, msg);
     aes_decrypt(&aes, secret, secret);    
     cat_buf(&pretty_secret, secret, aes_blocklen);
     memcpy(intercepted_secret, pretty_secret, aes_blocklen); 
     
     /* now reencrypt with our session key and send to bob */ 
     char* hacked_msg = NULL;
     char *armored_secret = NULL;
     aes_setkey(&aes, bm, 16);
     aes_encrypt(&aes, secret, secret);
     
     armored_secret = armor64(secret, aes_blocklen);
     cat_str(&hacked_msg, armored_secret);
     cat_str(&hacked_msg, "\n");
     cat_str(&hacked_msg, "\0");
   
     aes_clrkey(&aes);
     res = xstrdup (hacked_msg); 
     break;
  default:
    fprintf (stderr, "shouldn't happen\n");
    exit (1);
  }

  return res;
}


int
main (int argc, char **argv)
{
  char *msg_in = NULL;
  char *msg_out = NULL;
  int fd_out, fd_a_in, fd_a_out, fd_b_in, fd_b_out;

  if (argc != 6) {
    usage (argv[0]);
    /* does not return */
  }

  fd_out = atoi (argv[1]);
  fd_a_in = atoi (argv[2]);
  fd_a_out = atoi (argv[3]);
  fd_b_in = atoi (argv[4]);
  fd_b_out = atoi (argv[5]);
  
  setprogname (argv[0]);
  ri ();

  /* first message (from Alice) */
  if (!(msg_in = read_line (fd_a_in))) {
    fprintf (stderr, "error parsing alice's message:\n%s", msg_in);
    xfree (msg_in);
    msg_in = NULL;
    
    exit (1);
  }
  
  fprintf (stderr, "Received from Alice:\n====================\n%s\n", msg_in);

  /* compute what to send to Bob */
  msg_out = attack (FirstStage, msg_in);
  fprintf (stderr, "Sent to Bob:\n============\n%s\n", msg_out);
  write_chunk (fd_b_out, msg_out, strlen (msg_out));

  xfree (msg_in);
  msg_in = NULL;
  xfree (msg_out);
  msg_out = NULL;
  
  /* second message (from Bob) */
  if (!(msg_in = read_line (fd_b_in))) {
    fprintf (stderr, "error parsing bob's message:\n%s", msg_in);
    xfree (msg_in);
    msg_in = NULL;
    
    exit (1);
  }
  
  fprintf (stderr, "Received from Bob:\n==================\n%s\n", msg_in);
  
  /* compute what to send to Alice */
  msg_out = attack (SecondStage, msg_in);
  fprintf (stderr, "Sent to Alice:\n==============\n%s\n", msg_out);
  write_chunk (fd_a_out, msg_out, strlen (msg_out));

  xfree (msg_in);
  msg_in = NULL;
  xfree (msg_out);
  msg_out = NULL;
  
  /* last message (from Alice) */
  if (!(msg_in = read_line (fd_a_in))) {
    fprintf (stderr, "error parsing alice's message:\n%s", msg_in);
    xfree (msg_in);
    msg_in = NULL;
    
    exit (1);
  }
  
  fprintf (stderr, "Received from Alice:\n====================\n%s\n", msg_in);
  
  /* compute what to send to Bob, and record the payload in the global 
     variable intercepted_secret */
  msg_out = attack (LastStage, msg_in);
  fprintf (stderr, "Sent to Bob:\n============\n%s\n", msg_out);
  write_chunk (fd_b_out, msg_out, strlen (msg_out));

  xfree (msg_in);
  msg_in = NULL;
  
  xfree (msg_out);
  msg_out = NULL;
  
  /* write the intercepted payload to the launcher  */
  /*write_chunk (fd_out, intercepted_secret, aes_blocklen);*/
 /*  
   write_chunk (fd_out, "Attack not yet implemented!\n", 
                strlen("Attack not yet implemented!\n"));
   */

   write_chunk(fd_out, pretty_secret, strlen(pretty_secret));
   write_chunk(fd_out,"\n", 1);

  return 0;
}
