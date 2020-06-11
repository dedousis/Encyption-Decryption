#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/cmac.h>
#include <openssl/sha.h>
#include <assert.h>

#define BLOCK_SIZE 16


/* function prototypes */
void print_hex(unsigned char *, size_t);
void print_string(unsigned char *, size_t); 
void usage(void);
void check_args(char *, char *, unsigned char *, int, int);
void keygen(unsigned char *, unsigned char *, unsigned char *, int);
int encrypt(unsigned char *, int, unsigned char *, unsigned char *, 
    char *output_file,unsigned char *, int );
int decrypt(unsigned char *, int, unsigned char *, unsigned char *, 
    char *, int,unsigned char *);
void gen_cmac(unsigned char *, size_t, unsigned char *, unsigned char *, int);
int verify_cmac(unsigned char *, unsigned char *);



/* TODO Declare your function prototypes here... */
unsigned char* read_file(char*);
void write_to_file(char*,unsigned char* ,int);
void append_to_file(char*, unsigned char*,size_t);
long Get_File_Size(char*);


/*
 * Prints the hex value of the input
 * 16 values per line
 */
void
print_hex(unsigned char *data, size_t len)
{
	size_t i;

	if (!data)
		printf("NULL data\n");
	else {
		for (i = 0; i < len; i++) {
			if (!(i % 16) && (i != 0))
				printf("\n");
			printf("%02X ", data[i]);
		}
		printf("\n");
	}
	printf("---------------------------\n");
}


/*
 * Prints the input as string
 */
void
print_string(unsigned char *data, size_t len)
{
	size_t i;

	if (!data)
		printf("NULL data\n");
	else {
		for (i = 0; i < len; i++)
			printf("%c", data[i]);
		printf("\n");
	}
	printf("---------------------------\n");
}


/*
 * Prints the usage message
 * Describe the usage of the new arguments you introduce
 */
void
usage(void)
{
	printf(
	    "\n"
	    "Usage:\n"
	    "    assign_1 -i in_file -o out_file -p passwd -b bits" 
	        " [-d | -e | -s | -v]\n"
	    "    assign_1 -h\n"
	);
	printf(
	    "\n"
	    "Options:\n"
	    " -i    path    Path to input file\n"
	    " -o    path    Path to output file\n"
	    " -p    psswd   Password for key generation\n"
	    " -b    bits    Bit mode (128 or 256 only)\n"
	    " -d            Decrypt input and store results to output\n"
	    " -e            Encrypt input and store results to output\n"
	    " -s            Encrypt+sign input and store results to output\n"
	    " -v            Decrypt+verify input and store results to output\n"
	    " -h            This help message\n"
	);
	exit(EXIT_FAILURE);
}


/*
 * Checks the validity of the arguments
 * Check the new arguments you introduce
 */
void
check_args(char *input_file, char *output_file, unsigned char *password, 
    int bit_mode, int op_mode)
{
	if (!input_file) {
		printf("Error: No input file!\n");
		usage();
	}

	if (!output_file) {
		printf("Error: No output file!\n");
		usage();
	}

	if (!password) {
		printf("Error: No user key!\n");
		usage();
	}

	if ((bit_mode != 128) && (bit_mode != 256)) {
		printf("Error: Bit Mode <%d> is invalid!\n", bit_mode);
		usage();
	}

	if (op_mode == -1) {
		printf("Error: No mode\n");
		usage();
	}
}


/*
 * Generates a key using a password
 */
void
keygen(unsigned char *password, unsigned char *key, unsigned char *iv,
    int bit_mode)
{
	//SHA1(password,strlen((char *)password), iv); //call sha-1 hash function to make the unique IV
	
	/******
	Evpbytes to key derives a key and iv using a cipher algorithm for the key and sha1 hash 
	function for iv. We can add "salt" by replacing NULL with something else.Finally
	stores the key and iv in the variables als we can choose betweeb rounds

	********/
	assert(password!=NULL);

	if(bit_mode==256)
	{
		memset(key,0x0,32); //initialize to avoid memory garbage
		if(!EVP_BytesToKey(EVP_aes_256_ecb(),EVP_sha1(),NULL,(unsigned char *)password,strlen((const char *)password),1,key,NULL))
		{
			printf("EVP_BytesToKey failed\n");
		}

	}else if(bit_mode==128)
	{
		memset(key,0x0,16); //initialize to avoid memory garbage
		if(!EVP_BytesToKey(EVP_aes_128_ecb(),EVP_sha1(),NULL,(unsigned char *)password,strlen((const char *)password),1,key,NULL))
		{
			printf("EVP_BytesToKey failed\n");
		}
	}

}


/*
 * Encrypts the data
 * Encrypting consists of the following stages:
 * Setting up a context
 * Initialising the encryption operation
 * Providing plaintext bytes to be encrypted
 * Finalising the encryption operation
 */
int
encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
    unsigned char *iv, char *output_file,unsigned char *ciphertext, int bit_mode)
{
	assert(plaintext!=NULL);
	assert(ciphertext!=NULL);
	assert(key!=NULL);
	
	EVP_CIPHER_CTX *en;
	int ciphertext_len;
	int length=0;
	int AES_BLOCK_SIZE=128;

	/*max cipher len for n bytes*/
	ciphertext_len=plaintext_len+AES_BLOCK_SIZE;
	/***
		We need to initiliaze the context of EVP api 
	***/
	if(!(en = EVP_CIPHER_CTX_new())) 
	{
		ERR_print_errors_fp(stderr);
  		abort();
	}
	
	/**
		from here we will start the encryption by choosing which alogtithm we will use and afterwards i will provide the plain text to be encrypted 
	**/
	if(bit_mode==256)
	{
		/* Initialise the encryption operation. */
		if(EVP_EncryptInit_ex(en,EVP_aes_256_ecb(),NULL,key,NULL)!=1)
		{
			ERR_print_errors_fp(stderr);
  			abort();
		}
		/* Provide the message to be encrypted*/
		if(EVP_EncryptUpdate(en,ciphertext, &length, plaintext, plaintext_len)!=1)
		{
			ERR_print_errors_fp(stderr);
  			abort();
		}
		ciphertext_len=length;
		/* provide the last block*/
		if( EVP_EncryptFinal_ex(en, ciphertext + length, &length)!=1)
		{
			ERR_print_errors_fp(stderr);
  			abort();
		}
		ciphertext_len+=length;
	}else if(bit_mode==128){
		/* Initialise the encryption operation. */
		if(EVP_EncryptInit_ex(en,EVP_aes_128_ecb(),NULL,key,NULL)!=1)
		{
			ERR_print_errors_fp(stderr);
  			abort();
		}
		/* Provide the message to be encrypted*/
		if(EVP_EncryptUpdate(en,ciphertext, &length, plaintext, plaintext_len)!=1)
		{
			ERR_print_errors_fp(stderr);
  			abort();
		}
		ciphertext_len=length;
		/* provide the last block*/
		if( EVP_EncryptFinal_ex(en, ciphertext + length, &length)!=1)
		{
			ERR_print_errors_fp(stderr);
  			abort();
		}
		ciphertext_len+=length;
	}
	EVP_CIPHER_CTX_free(en);
	return ciphertext_len;
}


/*
 * Decrypts the data and returns the plaintext size
 */
int
decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
    unsigned char *iv,char *output_file, int bit_mode,unsigned char *plaintext)
{
	EVP_CIPHER_CTX *de;
	int plaintext_len=0,length;
	/***
		We need to initiliaze the context of EVP api 
	***/
	if(!(de = EVP_CIPHER_CTX_new())) 
	{
		ERR_print_errors_fp(stderr);
  		abort();
	}

	/* Initialise the decryption operation. */
	if(bit_mode==256){	

		if(EVP_DecryptInit_ex(de,EVP_aes_256_ecb(), NULL, key, NULL)!=1 )
		{
			ERR_print_errors_fp(stderr);
	  		abort();
		}
		/* Provide the message to be decrypted, and obtain the plaintext output.*/
		if( EVP_DecryptUpdate(de, plaintext, &length, ciphertext, ciphertext_len)!=1)
		{
			ERR_print_errors_fp(stderr);
	  		abort();
		}
		plaintext_len=length;
		/* provide the last block to be decrypted*/
		if(EVP_DecryptFinal_ex(de, plaintext+length, &length)!=1)
		{
			ERR_print_errors_fp(stderr);
	  		abort();
		}
		plaintext_len+=length;
		EVP_CIPHER_CTX_free(de);
	}else if(bit_mode==128){
		if(EVP_DecryptInit_ex(de,EVP_aes_128_ecb(), NULL, key, NULL)!=1 )
		{
			ERR_print_errors_fp(stderr);
	  		abort();
		}
		/* Provide the message to be decrypted, and obtain the plaintext output.*/
		if( EVP_DecryptUpdate(de, plaintext, &length, ciphertext, ciphertext_len)!=1)
		{
			ERR_print_errors_fp(stderr);
	  		abort();
		}
		plaintext_len=length;
		/* provide the last block to be decrypted*/
		if(EVP_DecryptFinal_ex(de, plaintext+length, &length)!=1)
		{
			ERR_print_errors_fp(stderr);
	  		abort();
		}
		plaintext_len+=length;
		EVP_CIPHER_CTX_free(de);
	}
	return plaintext_len;
}


/*
 * Generates a CMAC
 */
void
gen_cmac(unsigned char *data, size_t data_len, unsigned char *key, 
    unsigned char *cmac, int bit_mode)
{
	/* TODO Task D */
	CMAC_CTX *ctx_cmac;
	size_t cmac_len;

	//Iniitialize the context for evp api 
	if(!(ctx_cmac= CMAC_CTX_new()))
	{
		ERR_print_errors_fp(stderr);
	  	abort();
	}

	if(bit_mode==256)
	{
		/*initialize cmac and choose encryption algorith*/
		if(CMAC_Init(ctx_cmac,key,32,EVP_aes_256_ecb(),NULL)!=1)
		{
			ERR_print_errors_fp(stderr);
	  		abort();
		}
		/*provide the plaintext and the length*/
		if(CMAC_Update(ctx_cmac, data,data_len)!=1)
		{
			ERR_print_errors_fp(stderr);
	  		abort();
		}
		/* return the cmac generated */
		if(CMAC_Final(ctx_cmac, cmac, &cmac_len)!=1)
		{

			ERR_print_errors_fp(stderr);
	  		abort();
		}
	}else if(bit_mode==128){
		/*initialize cmac and choose encryption algorith*/
		if(CMAC_Init(ctx_cmac,key,16,EVP_aes_128_ecb(),NULL)!=1)
		{
			ERR_print_errors_fp(stderr);
	  		abort();
		}
		/*provide the plaintext and the length*/
		if(CMAC_Update(ctx_cmac, data,data_len)!=1)
		{
			ERR_print_errors_fp(stderr);
	  		abort();
		}
		/* return the cmac generated */
		if(CMAC_Final(ctx_cmac, cmac, &cmac_len)!=1)
		{

			ERR_print_errors_fp(stderr);
	  		abort();
		}

	}
	CMAC_CTX_free(ctx_cmac);
}
int
verify_cmac(unsigned char *cmac1, unsigned char *cmac2)
{
	int verify;

	verify = 0;
	if(strncmp((const char*)cmac1,(const char*)cmac2,16)==0)
	{
		verify=1;
	}
	return verify;
}



unsigned char*
read_file(char* input_file){
	FILE *fp = fopen(input_file, "rb");
	unsigned char* plaintext;
		long fsize=0;
		if (fp == NULL){
			printf("Error\n");
			return NULL;
		}else{
			fseek(fp, 0, SEEK_END);
			fsize = ftell(fp);
			fseek(fp, 0, SEEK_SET);  //same as rewind(fp);

			plaintext= malloc(fsize);
			if(!fread(plaintext,1, fsize, fp)){
				printf("Error\n");
				return NULL;
			}
			fclose(fp);
			return plaintext;
		}
}

void 
write_to_file(char* output_file,unsigned char* data,int length)
{
	FILE *fp;
	fp= fopen(output_file, "wb");
	fwrite(data, 1,length, fp);
	fclose(fp);
}

void
 append_to_file(char *output_file, unsigned char *cmac,size_t cmac_len){
	// Append CMAC sign into encrypted file 
	FILE *fp;
	fp= fopen(output_file, "ab");
	fwrite(cmac, 1, cmac_len, fp);
	fclose(fp);
}

long
Get_File_Size(char* filename)
{
    long size;
    FILE *f;
 
    f = fopen(filename, "rb");
    if (f == NULL) return -1;
    fseek(f, 0, SEEK_END);
    size = ftell(f);
    fclose(f);
 
    return size;
}

/*
 * Encrypts the input file and stores the ciphertext to the output file
 *
 * Decrypts the input file and stores the plaintext to the output file
 *
 * Encrypts and signs the input file and stores the ciphertext concatenated with 
 * the CMAC to the output file
 *
 * Decrypts and verifies the input file and stores the plaintext to the output
 * file
 */
int
main(int argc, char **argv)
{
	int opt;			/* used for command line arguments */
	int bit_mode;			/* defines the key-size 128 or 256 */
	int op_mode;			/* operation mode */
	char *input_file;		/* path to the input file */
	char *output_file;		/* path to the output file */
	unsigned char *password;	/* the user defined password */

	unsigned char iv[EVP_MAX_IV_LENGTH];
	//unsigned char key[EVP_MAX_KEY_LENGTH];
	unsigned char key_256[32];
	unsigned char key_128[16];
	unsigned char cmac[16];		//cmac is 16 bytes 

	unsigned char *plaintext;
	unsigned char *ciphertext;
	int plaintext_len,ciphertext_len,ciphertext_len_nosign;
	/* Init arguments */
	input_file = NULL;
	output_file = NULL;
	password = NULL;
	bit_mode = -1;
	op_mode = -1;
	plaintext=NULL;
	ciphertext=NULL;
	/*
	 * Get arguments
	 */
	while ((opt = getopt(argc, argv, "b:i:m:o:p:desvh:")) != -1) {
		switch (opt) {
		case 'b':
			bit_mode = atoi(optarg);
			break;
		case 'i':
			input_file = strdup(optarg);
			break;
		case 'o':
			output_file = strdup(optarg);
			break;
		case 'p':
			password = (unsigned char *)strdup(optarg);
			break;
		case 'd':
			/* if op_mode == 1 the tool decrypts */
			op_mode = 1;
			break;
		case 'e':
			/* if op_mode == 1 the tool encrypts */
			op_mode = 0;
			break;
		case 's':
			/* if op_mode == 1 the tool signs */
			op_mode = 2;
			break;
		case 'v':
			/* if op_mode == 1 the tool verifies */
			op_mode = 3;
			break;
		case 'h':
		default:
			usage();
		}
	}


	/* check arguments */
	check_args(input_file, output_file, password, bit_mode, op_mode);



	/* TODO Develop the logic of your tool here... */




	/* Initialize the library */
	ERR_load_crypto_strings();
  	OpenSSL_add_all_algorithms();
  	OPENSSL_config(NULL);

	/* Keygen from password */
	if(bit_mode==256){
		keygen(password,key_256,iv,bit_mode);
	}else{
		keygen(password,key_128,iv,bit_mode);
	}
	/* Operate on the data according to the mode */
	if(op_mode ==0)
	{
		/* encrypt */
		plaintext=read_file(input_file);
		plaintext_len=Get_File_Size(input_file);
		ciphertext=malloc(sizeof(char)*(plaintext_len+128));
		if(bit_mode==256){
			ciphertext_len=encrypt(plaintext,plaintext_len,key_256,iv,output_file,ciphertext,bit_mode);
		}else{
			ciphertext_len=encrypt(plaintext,plaintext_len,key_128,iv,output_file,ciphertext,bit_mode);
		}
		printf("File succesfully encrypted\n");
		write_to_file(output_file,ciphertext,ciphertext_len);
	}else if(op_mode==1)
	{
		/* decrypt */
		ciphertext=read_file(input_file);
		ciphertext_len=Get_File_Size(input_file);
		plaintext=malloc(sizeof(char)*(ciphertext_len+128));
		if(bit_mode==256){
			plaintext_len=decrypt(ciphertext,ciphertext_len,key_256,iv,output_file,bit_mode,plaintext);
		}else{
			plaintext_len=decrypt(ciphertext,ciphertext_len,key_128,iv,output_file,bit_mode,plaintext);
		}

		if(plaintext_len>0)
		{
			write_to_file(output_file,plaintext,plaintext_len);
			printf("File succesfully decrypted\n");
		}
		
	}else if(op_mode==2){

		/* sign */
		plaintext=read_file(input_file);
		plaintext_len=Get_File_Size(input_file);
		ciphertext=malloc(sizeof(char)*(plaintext_len+128));

		/*Encrypt the plaintext and concatenate the generated cmac at the end*/
		if(bit_mode==256){
			ciphertext_len=encrypt(plaintext,plaintext_len,key_256,NULL,output_file,ciphertext,bit_mode);
			gen_cmac(plaintext,plaintext_len,key_256,cmac,bit_mode);
			write_to_file(output_file,ciphertext,ciphertext_len);
			append_to_file(output_file,cmac,16);
			printf("File succesfully encrypted and signed\n");
		}else{
			ciphertext_len=encrypt(plaintext,plaintext_len,key_128,NULL,output_file,ciphertext,bit_mode);
			gen_cmac(plaintext,plaintext_len,key_128,cmac,bit_mode);
			
			write_to_file(output_file,ciphertext,ciphertext_len);
			append_to_file(output_file,cmac,16);
			printf("File succesfully encrypted and signed\n");
		}

	}else if(op_mode==3){
		/* verify */

		ciphertext=read_file(input_file);
		ciphertext_len=Get_File_Size(input_file);
		unsigned char* cmac1=&ciphertext[ciphertext_len-16];//contains the cmac from the encrypted file
		*(cmac1+16)='\0';

		ciphertext_len_nosign=ciphertext_len-16;
		unsigned char ciphertext_nosign[ciphertext_len_nosign];
		memcpy(ciphertext_nosign,ciphertext,ciphertext_len_nosign);//copy the enctypted content without sign
		plaintext=malloc(sizeof(char)*(ciphertext_len_nosign+128));

		if(bit_mode==256){
			plaintext_len=decrypt(ciphertext_nosign,ciphertext_len_nosign,key_256,iv,output_file,bit_mode,plaintext);
			gen_cmac(plaintext,plaintext_len,key_256,cmac,bit_mode);//cmac2,genrate cmac from decrypted plaintext
		}else{
			plaintext_len=decrypt(ciphertext_nosign,ciphertext_len_nosign,key_128,iv,output_file,bit_mode,plaintext);
			gen_cmac(plaintext,plaintext_len,key_128,cmac,bit_mode);//cmac2,,genrate cmac from decrypted plaintext
		}
		if(verify_cmac(cmac1,cmac)==1)
		{
			printf("CMAC Verification correct\n");
			if(plaintext_len>0)
			{
				write_to_file(output_file,plaintext,plaintext_len);
			}
		}else{
			printf("You got hacked\n");
		}

	}
	/* Clean up */
	free(input_file);
	free(output_file);
	free(password);


	/* END */
	return 0;
}
