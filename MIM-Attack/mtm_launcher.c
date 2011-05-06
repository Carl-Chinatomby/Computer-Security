#include "mtm.h"
#include <stdio.h>
#include <unistd.h>

#define ALICE_CMD "./mtm_alice" 
#define BOB_CMD   "./mtm_bob" 
#define MALLORY_CMD   "./mtm_mallory" 

/* simple utility to set up connection between mtm_alice, mtm_bob and
   mtm_mallory according to the diagram below: */

/*********************************************************************
 *    +-------+                +---------+                +-------+  *
 *    |       | 1-->--  -->--w |         | y--<--  --<--1 |       |  *
 *    | Alice |                | Mallory |                |  Bob  |  *
 *    |       | 0--<--  --<--x |         | z-->--  -->--0 |       |  *
 *    +-------+                +---------+                +-------+  *
 *         a                        m                        b       *
 *          \                       |                       /        *
 *           \                      |                      /         *
 *            \                     e                     /          *
 *             \               +---------+               /           *
 *              >-->--  -->-- c|         |d --<--  --<--<            *
 *                             | Launcher|                           *
 *                             |         |                           *
 *                             +---------+                           *
 *                                                                   *
 *  mtm_mallory takes file descriptors w, x, y, z from command line  *
 *                                                                   *
 ********************************************************************/

/* process id numbers for the spawned processes: alice, bob and mallory */
pid_t pids[3];

/* buffer to hold the data coming from alice, bob and mallory */
char *buf_a = NULL, *buf_b = NULL, *buf_m = NULL;

/* close all file descriptors in the array int fds[l], except for those 
   whose index is listed in the array except_idx before the terminating -1 */
void
close_fds (int *fds, int l, int *except_idx)
{
  int i;
  int *p;

  assert (fds);
  assert (except_idx);

  for (i = 0; i < l; i++) {
    for (p = except_idx; *p != -1; p++)
      /* don't close fds[i] if i occurs within except_idx */
      if (*p == i) break;

    /* if we run through all of except_idx without a match, then can close */
    if (*p == -1) close (fds[i]);
  }
}

void 
start_alice (int *fds, int idx_in, int idx_out, int idx_l)
{
  int except[2];
  char ascii_fd[4];
    
  /* set up the pipes */
  if (dup2 (fds[idx_in], 0) < 0 || dup2 (fds[idx_out], 1) < 0) {
    perror ("dup2");
    exit (1);
  }
    
  /* fds[idx_l] plays the role of a in the diagram above */
  /* close the pipes' descriptors in fds, except for the one at index idx_l */
  except[0] = idx_l; except[1] = -1;
  close_fds (fds, 14, except);
  
  /* pass fds[idx_l] via command line */
  sprintf (ascii_fd, "%d", fds[idx_l]);
  
  /* exec alice's code */
  execl (ALICE_CMD, "mtm_alice", "alice.priv", "alice.cert", "bob", 
	 ascii_fd, (char *)NULL);
  
  /* should never get here, unless we couldn't run bob */
  perror (ALICE_CMD);
  exit (1);    
}

void 
start_bob (int *fds, int idx_in, int idx_out, int idx_l)
{
  int except[2];
  char ascii_fd[4];
    
  /* set up the pipes */
  if (dup2 (fds[idx_in], 0) < 0 || dup2 (fds[idx_out], 1) < 0) {
    perror ("dup2");
    exit (1);
  }
    
  /* fds[idx_l] plays the role of b in the diagram above */
  /* close the pipes' descriptors in fds, except for the one at index idx_l */
  except[0] = idx_l; except[1] = -1;
  close_fds (fds, 14, except);
  
  /* pass fds[idx_l] via command line */
  sprintf (ascii_fd, "%d", fds[idx_l]);
  
  /* exec bob's code */
  execl (BOB_CMD, "mtm_bob", "bob.priv", "bob.cert", ascii_fd, 
	 (char *)NULL);
  
  /* should never get here, unless we couldn't run bob */
  perror (BOB_CMD);
  exit (1);    
}

void 
start_mallory (int *fds, int idx_w, int idx_x, int idx_y, int idx_z, int idx_m)
{
  int except[6];
  char ascii_fds[5][4];
    
  /* for v in {w, x, y, z, m}, fds[idx_v] plays role of v in diagram above */
  except[0] = idx_w; 
  except[1] = idx_x; 
  except[2] = idx_y; 
  except[3] = idx_z; 
  except[4] = idx_m; 
  except[5] = -1;
  close_fds (fds, 14, except);
  
  /* pass these fds via command line */
  sprintf (ascii_fds[0], "%d", fds[idx_w]);
  sprintf (ascii_fds[1], "%d", fds[idx_x]);
  sprintf (ascii_fds[2], "%d", fds[idx_y]);
  sprintf (ascii_fds[3], "%d", fds[idx_z]);
  sprintf (ascii_fds[4], "%d", fds[idx_m]);
  /* exec mallory's code */
  execl (MALLORY_CMD, "mtm_mallory", ascii_fds[0], ascii_fds[1], 
	 ascii_fds[2], ascii_fds[3], ascii_fds[4], (char *)NULL);
  
  /* should never get here, unless we couldn't run bob */
  perror (MALLORY_CMD);
  exit (1); 
}

void
get_outputs (int fd_a, int fd_b, int fd_m)
{
 /* we need to read once from each of alice, bob and mallory */
  if ((pids[0] != -1) && !(buf_a = read_line (fd_a))) {
    perror ("reading from Alice");
    
    exit (1);
  }
  pids[0] = -1;
  close (fd_a);

  if ((pids[1] != -1) && !(buf_b = read_line (fd_b))) {
    perror ("reading from Bob");
    
    exit (1);
  }
  pids[1] = -1;
  close (fd_b);

  if ((pids[2] != -1) && !(buf_m = read_line (fd_m))) {
    perror ("reading from Mallory");
    
    exit (1);
  }
  pids[2] = -1;
  close (fd_m);
}

void 
supervise (int *fds, int idx_c, int idx_d, int idx_e)
{
  int except[4];

 /* for v in {c, d, e}, fds[idx_v] plays role of v in diagram above */
  except[0] = idx_c; 
  except[1] = idx_d; 
  except[2] = idx_e; 
  except[3] = -1;
  close_fds (fds, 14, except);  

  get_outputs (fds[idx_c], fds[idx_d], fds[idx_e]);
 

  /* now compare notes */

  if (strcmp (buf_a, buf_b) == 0) {
    if (strcmp (buf_m, buf_a) == 0) {
      fprintf (stderr, "Successful man-in-the-middle attack!\n");
      fprintf (stderr, "Recovered secret was: %s\n", buf_m);
    }
    else {
      fprintf (stderr, "Mallory couldn't break the protocol.\n");
      fprintf (stderr, "The secret was: %s\nMallory said:\n%s\n",
	       buf_a, buf_m);
    }
  }
  else {
    fprintf (stderr, "Mallory disrupted the communication between Alice and Bob.\n"); 
    fprintf (stderr, "Shouldn't happen; secret must be recovered without the two parties noticing.\n"); 
    fprintf (stderr, "Alice's output:  %s\n", buf_a);
    fprintf (stderr, "Bob's output:  %s\n", buf_b);
    fprintf (stderr, "Mallorys's output:  %s\n", buf_m);
  } 
}

int 
main(int argc, char **argv)
{
  /* fds for pipes connecting Alice, Bob, Mallory and the launcher */
  int fds[14];
  /* alias pointers for each pair of fds */
  int *A_to_M = fds;
  int *M_to_B = fds + 2;
  int *B_to_M = fds + 4;
  int *M_to_A = fds + 6;
  int *A_to_L = fds + 8;
  int *B_to_L = fds + 10;
  int *M_to_L = fds + 12;
  
  if (argc != 1) {
    fprintf (stderr, "Launcher utility should be called with no args\n");
    
    exit (-1);
  }
  
  if (pipe (A_to_M) || pipe (M_to_B) || pipe (B_to_M) || pipe (M_to_A)
      || pipe (A_to_L) || pipe (B_to_L) || pipe (M_to_L)) {
    perror ("pipe");
    exit (-1);
  }
  
  if (!(pids[0] = fork ())) {
    /* Child process from first fork---Alice */
    start_alice (fds, 6, 1, 9);
  }
  else {
    /* Parent process from first fork---fork again to spawn bob */
    if (!(pids[1] = fork ())) {
      /* Child process from second fork---Bob */
      start_bob (fds, 2, 5, 11);
    }
    else {
      /* Parent process from second fork---fork again to spawn mallory */
      if (!(pids[2] = fork ())) {
	/* Child process from third fork---Mallory */
	start_mallory (fds, 13, 0, 7, 4, 3);
      }
      else {
	/* Parent process from third fork */
	/* just wait for the values that alice, bob and mallory will send */

	setprogname (argv[0]);
	supervise (fds, 8, 10, 12);
      }
    }
  }
   
  return 1;
}
  
