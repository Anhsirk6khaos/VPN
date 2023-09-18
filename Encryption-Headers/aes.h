
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>


/**************************************************************************
*This is where AES encryption and Decryption happens
**************************************************************************/

/*Encryption*/
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext) {

    /*Initalization Variables*/
    EVP_CIPHER_CTX *evpctx;
    int len;
    int ciphertext_len;

    /* Create and initialise the context */
    if (!(evpctx = EVP_CIPHER_CTX_new())) {
        perror("Initialization of Cipher Context is not working.......");
        exit(1);
    }

    /***********************************************************************
     * Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     ***********************************************************************/

    if (!(EVP_EncryptInit_ex(evpctx, EVP_aes_256_cbc(), NULL, key, iv))) {
        perror("Initialization of Encryption of Cipher is not working......");
        exit(1);
    }

    if (!(EVP_EncryptUpdate(evpctx, ciphertext, &len, plaintext, plaintext_len))) {
        perror("Update error with the Encryption of the cipher........");
        exit(1);
    }
    ciphertext_len = len;

    /**********************************************************************
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     **********************************************************************/

    if (!(EVP_EncryptFinal_ex(evpctx, ciphertext + len, &len))) {
        perror("Finalization of the encryption is not working......");
        exit(1);
    }
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(evpctx);

    return ciphertext_len;
}

/*Decryption*/

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext) {

  /*Initalization Variables*/
	EVP_CIPHER_CTX *evpctx;
	int len;
	int plaintext_len;

	/* Create and initialise the context */
  	if(!(evpctx = EVP_CIPHER_CTX_new())) 
  	{
  		perror("Initialization of de-Cipher Context is not working.......");
  		exit(1);
  	}

  /**************************************************************************
  * Initialise the decryption operation. IMPORTANT - ensure you use a key
	* and IV size appropriate for your cipher
	* In this example we are using 256 bit AES (i.e. a 256 bit key). The
	* IV size for *most* modes is the same as the block size. For AES this
	* is 128 bits 
  **************************************************************************/
	if(1 != EVP_DecryptInit_ex(evpctx, EVP_aes_256_cbc(), NULL, key, iv)) 
	{
  		perror("Initialization of Decryption of Cipher is not working......");
  		exit(1);
	}

   	/********************************************************************** 
    * Provide the message to be decrypted, and obtain the plaintext output.
   	* EVP_DecryptUpdate can be called multiple times if necessary
   	***********************************************************************/
  	if(1 != EVP_DecryptUpdate(evpctx, plaintext, &len, ciphertext, ciphertext_len))
    {
  		perror("Update error with the Decryption of the cipher........");
  		exit(1);
    }

	plaintext_len += len;

   	/******************************************************************** 
    *Finalise the decryption. Further plaintext bytes may be written at
   	* this stage.
   	*********************************************************************/
  	if(1 != EVP_DecryptFinal_ex(evpctx, plaintext + len, &len))
  	{
  		perror("Finalization of the decryption is not working......");
  		exit(1);
  	}

  	plaintext_len += len;

  	/* Clean up */
  	EVP_CIPHER_CTX_free(evpctx);

  	return plaintext_len;

}
