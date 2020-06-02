----------------------------------
Assignment Readme.txt
Dedousis Andreas 
---------------------------------
Command Line Arguments:

Compile using:	make
Clean using: 	make clean
How To Run:
	assign_1 -i in_file -o out_file -p passwd -b bits [-d | -e | -s | -v]
	assign_1 -h
----------------------------------
Files Includes With This Project:
	assign_1.c	encryptme_256.txt	
	Makefile	

-----------------------------------
In this assignment i am going to develop a symmetric encryption tool in C, using the
OpenSSL toolkit. The purpose of this assignment is to provide the opportunity to get
familiar with the very popular general-purpose cryptography toolkit and acquire hands-on
experience in implementing simple cryptographic applications. The tool will provide encryption,
decryption, CMAC signing and CMAC verification functionality.
More specifically, i am going to use the EVP API, found in the OpenSSL toolkit, which
provides a high-level interface to cryptographic functions. The cryptographic algorithm i am 
going to use is AES in Electronic Code Book (ECB) mode with both 128 and 256 bit modes.

Design Decisions & Project Issues:
	We have implemented the AES ecb as follows: First we are starting generating the proper key 
using keygen() function which takes the password given by the user and finally porduces a key of
either 16 or 32 bits depending on the type of AES(128,256).Here Task A is completed successfuly 
and now we are ready for Task B (encryption).The plaintext is been readed from the input file with 
read_file() and after the encrypt() is been called to produce the ciphertext using the plaintext, the
generated key,the plaintext length and the bit mode.Finally when ciphertext is ready we write it in
the output file with write_to_file().The decryption(Task C) of the ciphertext is similar to the encryption
but now we are using the Decrypt() with respectively arguments.These are the main functions we will use encrypt
and decrypt but we will add sign and verify features(Task D,E).As for sign feature we start by reading the plaintext
encrypt it and then generate the CMAC using gen_cmac() for plaintext, after these we append to the encrypted file the 
16 bytes CMAC sign.Final feature is verifing the CMAC and this is abit more complicated cause at first we have to 
extract the last 16 bytes of the ciphertext which are (possibly) the CMAC(cipher) then we have to decrypt the file without
the last 16 bytes and finally generate a new CMAC(plaintext).At the end we get these 2 CMACS and with verify_cmac()
we compare them to find them if they are identical,if they are, it means that noone in the middle has changed our file 
if not something bad has happend.
	As for project issues, i did not encounterd big problems during this project, the only issue i had it was when decrypting
i was losing the last 16 bytes of the file but it was easily corrected.
	Finally the given files (hy457_verifyme_128.txt)(hy457_verifyme_256.txt) were not succesfully verified because the CMAC
from the cipher text was different than the generated from the plaintext, which meanss that somenone in the middle before the decryption 
has interfere to the file and changed something.
--------------------------------------
