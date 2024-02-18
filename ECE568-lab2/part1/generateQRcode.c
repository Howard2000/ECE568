#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "lib/encoding.h"

//convert a string of hex values to a array of binary values
//e.g. 0xa -> 1010
//retrun a string of binary's
char * hex_to_binary_conversion(char * hex);

int
main(int argc, char * argv[])
{
	if ( argc != 4 ) {
		printf("Usage: %s [issuer] [accountName] [secretHex]\n", argv[0]);
		return(-1);
	}

	char *	issuer = argv[1];
	char *	accountName = argv[2];
	char *	secret_hex = argv[3];


	assert (strlen(issuer) <= 100);
	assert (strlen(accountName) <= 100);
	assert (strlen(secret_hex) <= 20);

	printf("\nIssuer: %s\nAccount Name: %s\nSecret (Hex): %s\n\n",
		issuer, accountName, secret_hex);

	// Create an otpauth:// URI and display a QR code that's compatible
	// with Google Authenticator

	//convert hex to binary
	char * secret_binary= hex_to_binary_conversion(secret_hex);
	if (secret_binary == NULL){
		printf("hex_to_binary_conversion error\n");
		return 0;
	}
	int secret_binary_length = strlen(secret_binary);

	//encode all inputs
	const char *encoded_accountName; 
	const char *encoded_issuer;
	int secret_base32_length = secret_binary_length*8/5;
	char *secret_base32 = malloc(sizeof(char)*secret_base32_length); 


	encoded_accountName = urlEncode(accountName);
	encoded_issuer = urlEncode(issuer);



	int ret = base32_encode(secret_binary, secret_binary_length, secret_base32, secret_base32_length);
	// int ret = base32_encode("\x12\x34\x56\x78\x90\x12\x34\x56\x78\x90", 10, secret_base32, secret_base32_length);
	printf("\nbase32: %s\n", secret_base32);


	char URL[1024];
	strcat(URL, "otpauth://totp/");
	strcat(URL, encoded_accountName);
	strcat(URL, "?issuer=");
	strcat(URL, encoded_issuer);
	strcat(URL, "&secret=");
	strcat(URL, secret_base32);
	strcat(URL, "&period=30");


	//otpauth://totp/ACCOUNTNAME?issuer=ISSUER&secret=SECRET&period=30
	

	//displayQRcode("otpauth://testing");
	displayQRcode(URL);

	return (0);
}


char * hex_to_binary_conversion(char * hex){
	int hex_length = strlen(hex);
	if (hex_length<=0){
		printf("Invalid hex number length: %d\n", hex_length);
		return NULL;
	}

	//allocate binary
	int binary_length = hex_length/2;//binary length = hex_length*4
	char * binary_result = malloc(sizeof(char)*binary_length+1); 
	binary_result[binary_length] = '\0';
	//conversion
	uint8_t digit = 0;
	uint8_t last_digit = 0;
	for (int i = 0; i < hex_length; i++){
		switch (hex[i]){
		case '0':
			digit = 0;
			break;
		case '1':
			digit = 1;
			break;
		case '2':
			digit = 2;
			break;
		case '3':
			digit = 3;
			break;
		case '4':
			digit = 4;
			break;
		case '5':
			digit = 5;
			break;
		case '6':
			digit = 6;
			break;
		case '7':
			digit = 7;
			break;
		case '8':
			digit = 8;
			break;
		case '9':
			digit = 9;
			break;
		case 'A':
			digit = 10;
			break;
		case 'B':
			digit = 11;
			break;
		case 'C':
			digit = 12;
			break;
		case 'D':
			digit = 13;
			break;
		case 'E':
			digit = 14;
			break;
		case 'F':
			digit = 15;
			break;
		default:
			printf("Invalid hex digit: %c\n", hex[i]);
			return NULL;
			break;
		}

		if (i%2 == 1){
			binary_result[i/2] = last_digit*16+digit;
		}

		last_digit = digit;

	}
	
	return binary_result;
}