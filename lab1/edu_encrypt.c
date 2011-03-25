#include "edu.h"

void
encrypt_file (const char *ctxt_fname, dckey *pk, int fin)
{
  /*************************************************************************** 
   * Task: Read the content from the file descriptor fin, encrypt it using
   *       pk, and place the resulting ciphertext in a file named ctxt_fname.
   *       The encryption should be CCA-secure (cf. first class), which is 
   *       the level of cryptographic protection that you should always 
   *       expect of any implementation of an encryption algorithm.
   * 
   * Below we describe a possible design, based on the so-called
   * `hybrid encryption' paradigm, but you are free to follow a different 
   * approach if you want, as long as it is also CCA-secure.
   * 
   * The `hybrid encryption' paradigm combines both public-key and symmetric
   * encryption functions: the idea is to 1) pick a random symmetric key K
   * and encrypt it under the public key pk; and 2) use K to encrypt the 
   * actual content read from the fin file descriptor using AES.  
   * For this to be secure, the public-key encryption scheme used to encrypt 
   * K must be CCA2-secure; an example is RSA-OAEP, an implementation of 
   * which is included in the library you are going to use 
   * (~class/src/dcrypt/pad.c, and ~class/src/dcrypt/rabin.c). 
   *
   * The symmetric encryption part must also be CCA-secure: one good approach
   * is to use AES in CBC-mode (cf. first class), and then append an HSHA-1 
   * mac of the resulting ciphertext. (Always mac after encrypting!)  
   * The libdcrypt library also contains implementations of AES 
   * (~class/src/dcrypt/aes.c) and of HSHA-1 (~class/src/dcrypt/sha1.c).  
   * However, you should take care of using AES in CBC-mode, as the
   * library only gives access to the basic AES block cipher functionality.
   *
   * Notice that the key used to compute the HSHA-1 mac must be different 
   * from the one used by AES. (Never use the same cryptographic key for 
   * two different purposes: bad interference could occur.) 
   * For this reason, the key K encrypted under the public key pk actually 
   * consists of two pieces, one for AES and one for  HSHA-1.  
   * The length of both pieces (and hence the cryptographic strength of the
   * encryption) is specified by the constant CCA_STRENGTH in edu.h.
   *
   * Recall that AES can only encrypt blocks of 64 bits, so you should use
   * some padding in the case that the length (in bytes) of the plaintext 
   * is not a multiple of 8.  This should be done in a way that allow proper 
   * decoding after decryption: in particualr,  the recipient must have a way 
   * to know where the padding begins so that it can be chopped off. 
   * One possible design is to add enough 0 bytes to the plaintext so as to
   * make its length a multiple of 8, and then append a byte at the end
   * specifying how many zero-bytes were appended.
   *
   * Thus, the overall layout of an encrypted file will be:
   *
   *         +-------+---+---+----------------------+--------+
   *         | X_len | X | Y | HSHA-1 (K_HSHA-1, Y) | padlen |
   *         +-------+---+---+----------------------+--------+
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
   ***************************************************************************/

   int fout, finr;
  /* Create the ciphertext file---the content will be encrypted, 
   * so it can be world-readable! */
   if ((fout = open(ctxt_fname, O_WRONLY | O_TRUNC | O_CREAT, 0777)) == -1)
     {
        printf("Error creating output file!");
        exit(0);
     }

  /* initialize the pseudorandom generator */
   const int seed_size = 128/8;
   char seed[seed_size];

   finr = open("/dev/random", O_RDONLY);
   if(read(finr, seed, seed_size) <= 0)
     {
        printf("Error, Reading Random file!");
        exit(0);
     }
   close(finr);
   printf("read the random seed: %s\n", seed); /*testcode*/
   prng_seed(seed, seed_size);
 
  /* Pick two random keys */
   u_int64_t AESkey, SHA1key;
   AESkey = prng_gethyper();
   SHA1key = prng_gethyper();
   
   /*
   printf("The AES key is: %d\n", AESkey);
   printf("The SHA1 key is %d\n", SHA1key);   
   */
   
   char AESchar[seed_size], SHA1char[seed_size];
   puthyper(AESchar, AESkey);
   puthyper(SHA1char, SHA1key);   
   
   /*
   printf("The AESchar is: %s\n", AESchar);
   printf("The SHA1char is: %s\n", SHA1char);
   */
  
  /* use the first key for the CBC-AES encryption ...*/
  /* ... and the second part for the HMAC-SHA1 */\
  /* Encrypt both keys under the public key pk */

   char *armorAES, *armorSHA1;
   armorAES = armor64(AESchar, seed_size);
   armorSHA1 = armor64(SHA1char, seed_size);
   
   
   printf("The armoredAES is: %s\n", armorAES);
   printf("The armoredSHA1 is: %s\n", armorSHA1);
   
   
   int fullkeylen = armor64len(armorAES)+armor64len(armorSHA1);
   char fullkey[fullkeylen];
   strcpy(fullkey, armorAES);
   
   /*
   printf("The fullkey with armorAES is now: %s\n", fullkey);
   */
    
   strcat(fullkey, armorSHA1);
   
   /*
   printf("the fullkey with sha1 appended is now: %s\n", fullkey);
   */
   
   char *enckey = dcencrypt(pk, fullkey);
   int keylenbytes = 2;
   
   short enckeyint = (short) strlen(enckey);
   
   
   printf("the encrypted full key is %s\n", enckey);
   printf("the length of full key is %d\n", enckeyint);
   
   
  write(fout, &enckeyint, keylenbytes*sizeof(char) );
   
  /* then, write the ciphertext that encapsulates the two keys */
  write(fout, enckey, enckeyint*sizeof(char));
   
  /*
  printf("successfully wrote the fullkey"); 
  */
 /* Now start processing the actual file content using symmetric encryption */
  /* Remember that CBC-mode needs a random IV (Initialization Vector) */
   
   int blocksize = 128/8; 
   char data[blocksize+1], encdata[blocksize+1], ciphertext[blocksize+1];
   aes_ctx aes;
   aes_setkey(&aes,armorAES,armor64len(armorAES));
   
   /*
   printf("initialized AEs with key length %d\n", armor64len(armorAES));
   */
   
   sha1_ctx sc;
   hmac_sha1_init(armorSHA1, armor64len(armorSHA1), &sc);
   
   /*
   printf("initialized sha1 with key length %d\n", armor64len(armorSHA1));
   */
   
   /* create initialization vector */
   
   prng_getbytes(ciphertext, blocksize);
   int bytesread = 0;
   
   
   printf("initialization vector is: %s\n", ciphertext);
   
   /*write initialization vector */
    write(fout, ciphertext, blocksize*sizeof(char));


  /* Compute the HSHA-1 mac while you go */

  /* CBC (Cipher-Block Chaining)---Encryption
   * xor the previous ciphertext's block with the next plaintext's block;
   * then encrypt it with AES and write the resulting block */
   int i;
   while((bytesread = read(fin, data, blocksize)) == blocksize)
     {
        i = 0;
        data[blocksize]='\0';
        printf("just read %d bytes\n", bytesread);
        printf("just read this block: %s\n", data);
        printf("the current ciphertext is %s\n", ciphertext);
        for (i=0; i<blocksize; i++)
          {
             encdata[i] = ciphertext[i] ^ data[i];
             
          }
        printf("just did the xor and its value is: %s\n", encdata);
        aes_encrypt(&aes,ciphertext,encdata);
        printf("just did the aes and and the result is: %s\n", ciphertext);
        hmac_sha1_update(&sc, ciphertext, blocksize);
        printf("performed sha1 update\n");     
        write(fout, ciphertext, blocksize*sizeof(char));
     }
         
  /* Don't forget to pad the last block with trailing zeroes */

    /* pad last block */
   
   char padlen = 0;
   if ((bytesread < blocksize) && (bytesread >0))
     {  
        printf("the last block before padding is: %s\n", data);
        for(i=bytesread; i<blocksize; i++)
          {
             data[i]=0;
             
          }
        padlen = blocksize - bytesread;
        printf("the last block after padding is: %s\n", data);
         
        for (i=0; i<blocksize; i++)
          {
             encdata[i] = ciphertext[i] ^ data[i];
             
          }
        printf("the xor on the last block is: %s\n", encdata);
        aes_encrypt(&aes, ciphertext,encdata);
        printf("the last block encrpted is: %s\n", ciphertext);
        write(fout, ciphertext, blocksize*sizeof(char));
        hmac_sha1_update(&sc, ciphertext, blocksize );
     }
  /* write the last chunk */
  /* Finish up computing the HSHA-1 mac and write the 20-byte mac after
   * the last chunk of the CBC ciphertext */
  
   int hmaclen = 20;
   /*
   char *hmac_out = (char *) malloc(hmaclen*sizeof(char));
   */
   char hmac_out[hmaclen];
   hmac_sha1_final(armorSHA1, armor64len(armorSHA1), &sc, hmac_out);
   write(fout, hmac_out, hmaclen*sizeof(char));
   printf("the hmac was: %s\n", hmac_out);
   /* Remember to write a byte at the end specifying how many trailing zeroes
   * (possibly none) were added */

   printf("the paddlength is: %s\n", &padlen);
    int padint = (int) padlen;
   printf("the padding int is: %d\n", padint);
   int bytes_wrote;
   bytes_wrote = write(fout, &padlen, sizeof(char));
  printf("successfully wrote %d bytes for padding\n", bytes_wrote);
   /* before the end, don't forget to wipe out the variables that were used 
   * to hold sensitive information, such as the symmetric keys for AES and
   * HSHA-1 */
  
   aes_clrkey(&aes);
   close(fout);
   /* print encrypted data */
/*
   printf("The Final Encrypted data is: %s", encdata); 
 */
}

void 
usage (const char *pname)
{
  printf ("Simple File Encryption Utility\n");
  printf ("Usage: %s PK-FILE PTEXT-FILE CTEXT-FILE\n", pname);
  printf ("       Exits if either PK-FILE or PTEXT-FILE don't exist, or if\n");
  printf ("       a public key pk cannot be found in PK-FILE.  Otherwise,\n");
  printf ("       encrpyts the content of PTEXT-FILE under pk, and place\n");
  printf ("       the resulting ciphertext in CTEXT-FILE.\n");
  printf ("       (If CTEXT-FILE existed and a valid public key was found\n");
  printf ("        PK-FILE, previous content of CTEXT-FILE is lost.)\n");

  exit (1);
}

int 
main (int argc, char **argv)
{
  int fdpk, fdptxt;
  dckey *pk;


  if (argc != 4) {
    usage (argv[0]);
  }   /* Check if argv[1] and argv[2] are existing files */
  else if (((fdpk = open (argv[1], O_RDONLY)) == -1)
	   || ((fdptxt = open (argv[2], O_RDONLY)) == -1)) {
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
    
    /* Import public key from argv[1] */
    if (!(pk = import_pub_from_file (fdpk))) {
      printf ("%s: no public key found in %s\n", argv[0], argv[1]);
      
      close (fdpk);
      exit (2);
    }
    close (fdpk);

    /* Enough setting up---let's get to the crypto... */
    encrypt_file (argv[3], pk, fdptxt);    

    dcfree (pk);
    close (fdptxt);
  }

  return 0;
}

