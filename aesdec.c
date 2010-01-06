/*
 * AES file decryption tool 
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
 * simple file based decryption tool
 * it uses AES256 for decryption and CBC mode
 *
 * usage: aesdec <infile> <outfile>
 * tool will prompt for key
 */
int main(int argc, char *argv[])
{
    int n;
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
        printf("usage: aesafe-enc <infile> <outfile>\n");
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
	 * read file header, check magic number
	 * and get length of original input file
	 */
	fread(buffer, sizeof(buffer), 1, infp);
	if (memcmp(buffer, "ACBC ", 5) != 0) {
		printf("error: wrong input file format\n");
		exit(1);
	}
	sscanf(buffer, "ACBC %ld", &len);

    while (!feof(infp)) {
		memset(buffer, 0, sizeof(buffer));
		/*
		 * read 512 byte block
		 */
        n = fread(buffer, 1, sizeof(buffer), infp);
		if (len < 0) {
			/*
			 * we're done already so we just read until EOF
			 */
			continue;
		}
		/*
		 * decrypt block
		 */
		decryptCBC((unsigned char *)buffer, sizeof(buffer), 
				   (unsigned char *)key, strlen(key), iv);
		/*
		 * the last block may be padded with 0x00s so we have to
		 * determine how many bytes we have to take from it
		 */
		fwrite(buffer, (n > len) ? len : n, 1, outfp);
		/*
		 * calculate how many bytes still are required
		 */
		len -= n;

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
        

