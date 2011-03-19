#include "edu.h"

void
decrypt_file (const char *ptxt_fname, dckey *sk, int fin)
{
  /*************************************************************************** 
   * Task: Read the ciphertext from the file descriptor fin, decrypt it using
   *       sk, and place the resulting plaintext in a file named ptxt_fname.
   *
   * This procedure basically `undoes' the operations performed by edu_encrypt;
   * it expects a ciphertext featuring the following structure (please refer 
   * to the comments in edu_encrypt.c for more details):
   *
   *        +-------+---+---+----------------------+--------+
   *        | X_len | X | Y | HSHA-1 (K_HSHA-1, Y) | padlen |
   *        +-------+---+---+----------------------+--------+
   *
   * where X = PKE (pk, {K_AES, K_HSHA-1}),
   *       X_len = length of X in bytes
   *       Y = CBC-AES (K_AES, {plaintext, 0^padlen})
   *       padlen = no. of zero-bytes added to the plaintext to make its
   *                length a multiple of 8
   * 
   * Moreover, X_len is two-byte-long, X consists of X_len bytes, the length
   * of Y (in bytes) is a multiple of 8, the hash value HSHA-1 (K_HSHA-1, Y) 
   * is 20-byte-long, and padlen is a sigle byte.
   * 
   * Notice that reading in the value of X (i.e., the piece of ciphertext that
   * encapsulates the symmetric keys used to encrypt and mac the actual file
   * content) it's easy, as its length is prefixed, so we know exactly how many
   * bytes to read.  

   * Reading Y (and then the mac and the pad length) it's a bit trickier: 
   * below we sketch one possible approach, but you are free to implement this
   * as you wish.
   *
   * The idea is based on the fact that the ciphertext files ends with 
   * 21 bytes (i.e., sha1_hashsize + 1) used up by the HSHA-1 mac and by the 
   * pad length.  Thus, we will repeatedly attempt to perform `long read' of 
   * (aes_blocklen + sha1_hashsize + 2) bytes: once we get at the end of the 
   * ciphertext and only the last chunk of Y has to be read, such `long read'
   * will encounter the end-of-file, at which point we will know where Y ends,
   * and how to finish reading the last bytes of the ciphertext.
   */

   /*
   int fout;
   char *decrypted_data = NULL;
   int length = 5;
   if ((fout = open(ptxt_fname, O_WRONLY)) == -1)
     {
        printf("Error Opening Outfile");
        exit(0);
     }
   write(fout, decrypted_data, len);
   */    
   
       
   
  /* first, read X_len */

  /* now we read X */

  /* Decrypt this header to recover the symmetric keys K_AES and K_HSHA-1 */
 
  /* use the first symmetric key for the CBC-AES decryption ...*/
  /* ... and the second for the HMAC-SHA1 */

  /* Reading Y */
  /* First, read the IV (Initialization Vector) */

  /* compute the HMAC-SHA1 as you go */

  /* Create plaintext file---may be confidential info, so permission is 0600 */

  /* CBC (Cipher-Block Chaining)---Decryption
   * decrypt the current block and xor it with the previous one 
   */

  /* Recall that we are reading sha_hashsize + 2 bytes ahead: now that 
   * we just consumed aes_blocklen bytes from the front of the buffer, we
   * shift the unused sha_hashsize + 2 bytes left by aes_blocklen bytes 
   */
  
  /* write the decrypted chunk to the plaintext file */

  /* now we can finish computing the HMAC-SHA1 */
  
  /* compare the HMAC-SHA1 we computed with the value read from fin */
  /* NB: if the HMAC-SHA1 mac stored in the ciphertext file does not match 
   * what we just computed, destroy the whole plaintext file! That means
   * that somebody tampered with the ciphertext file, and you should not
   * decrypt it.  Otherwise, the CCA-security is gone.
   */

  /* write the last chunk of plaintext---remember to chop off the trailing
   * zeroes, (how many zeroes were added is specified by the last byte in 
   * the ciphertext (padlen).
   */

  /* before the end, don't forget to wipe out the variables that were used 
   * to hold sensitive information, such as the symmetric keys for AES and
   * HSHA-1 */
   
}

void 
usage (const char *pname)
{
  printf ("Simple File Decryption Utility\n");
  printf ("Usage: %s SK-FILE CTEXT-FILE PTEXT-FILE\n", pname);
  printf ("       Exits if either PK-FILE or CTEXT-FILE don't exist, or\n");
  printf ("       if a private key sk cannot be found in SK-FILE.\n");
  printf ("       Otherwise, tries to use sk to decrypt the content of\n");
  printf ("       CTEXT-FILE: upon success, places the resulting plaintext\n");
  printf ("       in PTEXT-FILE; if a decryption problem is encountered\n"); 
  printf ("       after the processing started, PTEXT-FILE is truncated\n");
  printf ("       to zero-length and its previous content is lost.\n");

  exit (1);
}

int 
main (int argc, char **argv)
{
  int fdsk, fdctxt;
  dckey *sk;


  if (argc != 4) {
    usage (argv[0]);
  }   /* Check if argv[1] and argv[2] are existing files */
  else if (((fdsk = open (argv[1], O_RDONLY)) == -1)
	   || ((fdctxt = open (argv[2], O_RDONLY)) == -1)) {
    if (errno == ENOENT) {
      usage (argv[0]);
    }
    else {
      perror (argv[0]);
      
      exit (-1);
    }
  }   
  else {
    setprogname (argv[0]);

    /* Import private key from argv[1] */
    if (!(sk = import_priv_from_file (fdsk))) {
      printf ("%s: no private key found in %s\n", argv[0], argv[1]);
      
      close (fdsk);
      exit (2);
    }
    close (fdsk);

    /* Enough setting up---let's get to the crypto... */
    decrypt_file (argv[3], sk, fdctxt);    

    dcfree (sk);
    close (fdctxt);
  }

  return 0;
}
