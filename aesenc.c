/*
 * AES file encryption tool 
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include "aeslib.h"


/*
 * simple file based encryption tool
 * it uses AES256 for encryption and CBC mode
 *
 * usage: aesenc <infile> <outfile>
 * tool will prompt for key
 */
int main(int argc, char *argv[])
{
    long len;
    char key[512] = {0};
    char buffer[512];
    FILE *infp, *outfp;
	/*
	 * ensure you use the same initialization vector
	 * for encryption and decrpytion
	 */
    unsigned char iv[] = {
        0x22, 0x10, 0x19, 0x64,
        0x10, 0x19, 0x64, 0x22,
        0x19, 0x64, 0x22, 0x10,
        0x64, 0x22, 0x10, 0x19
    };

    if (argc < 3) {
        printf("usage: aesenc <infile> <outfile>\n");
        exit(1);
    }
    
    infp = fopen(argv[1], "r");
    if (infp == 0) {
        printf("cannot open file %s: %s\n", argv[1], strerror(errno));
        exit(1);
    }
    outfp = fopen(argv[2], "w+");
    if (outfp == 0) {
        printf("cannot open file %s: %s\n", argv[2], strerror(errno));
        exit(1);
    }

	/*
	 * prompt for key and read it from stdin
	 */
	printf("key>");
	fgets(key, sizeof(key), stdin);
    trimKey(key);

	/*
	 * output file starts with a 512-byte header
	 * containing magic number "ACBC"
	 * followed by a blank and the original length of the inut file
	 * the rest of the file contains a number of 512 byte blocks
	 * of ciphertext, last block is padded with 0x00
	 */
	memset(buffer, 0, sizeof(buffer));

	/*
	 * determine length of input file by setting fp to eof
	 * and reading the file position
	 */
	fseek(infp, 0, SEEK_END);
	len = ftell(infp);
	/*
	 * set fp back to bof
	 */
	fseek(infp, 0, SEEK_SET);

	/*
	 * set magic number and length and write header to output file
	 */
	sprintf(buffer, "ACBC %ld", len);
	fwrite(buffer, sizeof(buffer), 1, outfp);
	if (ferror(outfp)) {
		printf("error writing header to output file %s\n", argv[2]);
		fclose(infp);
		fclose(outfp);
		exit(1);
	}

	while (!feof(infp)) {
        memset(buffer, 0, sizeof(buffer));
        fread(buffer, sizeof(buffer), 1, infp);
		/*
		 * encrypt 512 byte block
		 */
		encryptCBC((unsigned char*)buffer, sizeof(buffer), 
				   (unsigned char*)key, strlen(key), iv);
		/*
		 * write block to output file
		 */
		fwrite(buffer, sizeof(buffer), 1, outfp);

		/*
		 * check for I/O errors
		 */
		if (ferror(outfp) || ferror(infp)) {
			if (ferror(outfp)) {
				printf("error writing to output file %s\n", argv[2]);
			}
			else {
				printf("error reading from input file %s\n", argv[1]);
			}
			fclose(infp);
			fclose(outfp);
			exit(1);
		}
	}
    fclose(infp);
    fclose(outfp);
	
	return 0;
}
        

