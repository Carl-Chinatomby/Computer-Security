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
 
          
  /* first, read X_len */

   int x_lensize=2;
   short x_len;
   read(fin, &x_len, x_lensize*sizeof(char));

   
   printf("Read for xlen: %d\n", x_len);
   
   
   /* now we read X */
   char x[x_len];
   read(fin, x, x_len);
   
   printf("read for xvalue: %s\n", x);
   
    
   /* Decrypt this header to recover the symmetric keys K_AES and K_HSHA-1 */
   char *fullkey;
   fullkey = dcdecrypt(sk, x);
   
   /*
   printf("the fullkey after dcdecrypt is: %s\n", fullkey);
   */
   
   int key_size = strlen(fullkey)/2;
   
   /*
   printf("The key size is calculated to be: %d\n", key_size);
   */
   
   char  K_AES[key_size+1], K_SHA1[key_size]; 

   strncpy(K_AES, fullkey, key_size);
   K_AES[key_size]='\0';
   printf("The armored AES key is: %s\n", K_AES);
   
   strcpy(K_SHA1, fullkey+key_size);
   printf("The armored SHA1key is: %s\n", K_SHA1);
   
  /* use the first symmetric key for the CBC-AES decryption ...*/
  /* ... and the second for the HMAC-SHA1 */
   aes_ctx aes;
   aes_setkey(&aes, K_AES, key_size);
   sha1_ctx sc;
   hmac_sha1_init(K_SHA1, key_size, &sc);

  /* Reading Y */
  /* First, read the IV (Initialization Vector) */
   int blocksize=128/8;
   char prev_block[blocksize+1], cur_block[blocksize+1], decdata[blocksize+1], plaintxt[blocksize+1];
   read(fin, prev_block, blocksize);
   prev_block[blocksize] = '\0';
   printf("the initialization vector is: %s\n", prev_block);
   hmac_sha1_update(&sc, prev_block, blocksize);
  /* compute the HMAC-SHA1 as you go */

  /* Create plaintext file---may be confidential info, so permission is 0600 */
   int fout;
   if ((fout = open(ptxt_fname, O_WRONLY | O_TRUNC | O_CREAT, 0600)) == -1)
     {
        printf("Error Creating Output file!");
        exit(0);
     }
   
  /* CBC (Cipher-Block Chaining)---Decryption
   * decrypt the current block and xor it with the previous one 
   */
   
   /*calculate length of ciphertext since we know hmac + pad =21*/

   int cursor = lseek(fin, 0, SEEK_CUR);
   printf("The cursor is at: %d\n", cursor);
   
   int end = lseek(fin, 0, SEEK_END);
   printf("The end of file is at: %d\n", end);
    
   int hmaclen = 20;
   int paddingsize = 1;
   int y_len = end - cursor - hmaclen - paddingsize;
   int y_read = 0;
   
   int current =lseek(fin, cursor, SEEK_SET);
   printf("we are currently at: %d\n", current);
   
   int bytes_read = 0;
   int i =0;
   while (y_read < y_len)
     {
        bytes_read = read(fin, cur_block, blocksize);
        cur_block[blocksize] = '\0';
        
        y_read +=bytes_read;
        printf("just read %s\n", cur_block);
        printf("read %d out of %d", y_read, y_len);
        hmac_sha1_update(&sc, cur_block, blocksize);
        aes_decrypt(&aes, decdata, cur_block);
        decdata[blocksize] = '\0';
        printf("decrypted block is: %s\n", decdata);
        for (i = 0; i<blocksize; i++)
          {
             plaintxt[i]=decdata[i] ^ prev_block[i];
          }
        plaintxt[blocksize] ='\0';
        printf("result of the xor is: %s\n", plaintxt);
        write(fout,plaintxt, blocksize*sizeof(char));
      
     }
   printf("out of while loop now after reading %d bytes in last block\n", bytes_read);
   /*now we need to decrypt the last block
   lets read the hmac and the paddingn and unpad the last block
   */
  
 
   char hmac[hmaclen+1], verhmac[hmaclen];
   char padding;
   read(fin, hmac, hmaclen);
   read(fin, padding, sizeof(char));
   hmac[hmaclen] = '\0';
   printf("the actual hmac is: %s\n", hmac);
   hmac_sha1_final(K_SHA1, key_size, &sc, verhmac);
   printf("the calculated hmac is: %s\n", verhmac);
   
   printf("the padding is: %s\n", padding);
   int pad = (int) padding;
   printf("the pad in int is %d\n", pad);
   
   
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
   aes_clrkey(&aes);
   close(fout);
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
