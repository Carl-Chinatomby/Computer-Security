#include "mtm.h"

enum {FirstStage = 0, SecondStage, LastStage};

char intercepted_secret[aes_blocklen];

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
  flow2 *from_b = NULL;
  char *payload = NULL;
  char *res = NULL;

  switch (s) {
  case FirstStage:
    from_a = process_ke_msg (msg, NULL);
    state = NULL;
    /* don't do nothing for now */
    res = xstrdup (msg);
    break;
  case SecondStage:
    from_b = process_ke_reply (from_a, msg, NULL);
    state = NULL;
    /* don't do nothing for now */
    res = xstrdup (msg);
    break;
  case LastStage:
    payload = NULL; 
    state = NULL;
    /* don't do nothing for now */
    res = xstrdup (msg); 
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
  write_chunk (fd_out, "Attack not yet implemented!\n", 
	       strlen ("Attack not yet implemented!\n"));

  return 0;
}
