#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int
foo ( char *arg )
{
	char	buf[256];
	int	i, len;

	len = strlen(arg);
	if (len > 272) len = 272;
  
	for (i = 0; i <= len; i++)
		buf[i] = arg[i];

	// printf("len = 0x%x\n", len);
	// printf("len = 0d%d\n", len);
	// printf("i = 0x%x\n", i);
	// printf("i = 0d%d\n", i);

	return (0);
}

int
lab_main ( int argc, char *argv[] )
{
	int	t = 2;

	printf ("Target2 running.\n");

	if (argc != t)
	{
		fprintf ( stderr, "target2: argc != 2\n" );
		exit ( EXIT_FAILURE );
	}

	foo ( argv[1] );

	return (0);
}
