/*
 * AES encryption library
 *
 * Copyright (C) 2009 wolfmuel[at]gmail.com
 *
 * This program is free software; you can redistribute it and/or modify 
 * it under the terms of the GNU General Public License as published by 
 * the Free Software Foundation; either version 3 of the License, or any 
 * later version.
 *
 * This program is distributed in the hope that it will be useful, but 
 * WITHOUT ANY WARRANTY; without even the implied warranty of 
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License 
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

/*
 * ECB encryption routine
 * size of 'input' has to be multiple of 16
 * 'input' contains ciphertext on exit
 * returns 0 if parameters are invalid and 1 otherwise 
 */  
int encrypt(unsigned char *input, int len, unsigned char *key, int klen);

/*
 * ECB decryption routine
 * size of 'input' has to be multiple of 16
 * 'input' contains cleartext on exit
 * returns 0 if parameters are invalid and 1 otherwise 
 */  
int decrypt(unsigned char *input, int len, unsigned char *key, int klen);


/*
 * CBC encryption routine
 * size of 'input' has to be multiple of 16
 * 'input' contains ciphertext on exit
 * 'iv' must hold a 16 byte initialization vector
 * returns 0 if parameters are invalid and 1 otherwise 
 */  
int encryptCBC(unsigned char *input, int len, unsigned char *key, 
               int klen, unsigned char *iv);

/*
 * CBC decryption routine
 * size of 'input' has to be multiple of 16
 * 'input' contains cleartext on exit
 * 'iv' must hold the same 16 byte initialization vector
 * that has been used to encrypt the cleartext
 * returns 0 if parameters are invalid and 1 otherwise 
 */  
int decryptCBC(unsigned char *input, int len, unsigned char *key, 
               int klen, unsigned char *iv);

/*
 * key should not have and \r or \n 
 * character at the end to ensure compatibility
 */
void trimKey(char *key);
