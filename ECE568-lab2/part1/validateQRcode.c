#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <stdlib.h>
#include <math.h>

#include "lib/sha1.h"

#define debug_print

#define timer_len 8

//convert a string of hex values to a array of binary values
//e.g. 0xa -> 1010
//retrun a string of binary's
int hex_to_binary_conversion(char * hex, uint8_t ** binary_result);

static int
validateTOTP(char * secret_hex, char * TOTP_string)
{	
	printf("\nvalidateTOTP:\n");
	printf("secret hex: %s\n", secret_hex);
	
	// HOTP(K,T) = Truncate(HMAC(K,T))
	//HMAC = H[(K XOR opad) + H((K XOR ipad) + M)] , M=T
	//calculate T, store it in binary format
	
	time_t current_time = time(NULL);
	printf("current time: %s", ctime(&current_time));
	printf("time in sec: %d\n", current_time);

	unsigned long int timer = 0;
	timer = current_time/30;
	printf("time in int: %ld\n", timer);
	printf("size of int in bytes: %ld\n", sizeof(unsigned long int));

	// timer = 123456;
	
	uint8_t t[8], temp_t[8];
	
	//I have to do this because how weird intel memory structure is!!!!
	//it will copy this least significant byte to t[0], but I want t[0] to store the most significant byte so it can be correctly attached to the binary stream of Key for HMAC
	memcpy(temp_t, &timer, timer_len);
	t[0] = temp_t[7]; //least significant byte of T
	t[1] = temp_t[6];
	t[2] = temp_t[5];
	t[3] = temp_t[4]; 
	t[4] = temp_t[3];
	t[5] = temp_t[2];
	t[6] = temp_t[1]; 
	t[7] = temp_t[0]; //most significant byte of T

	//	memory_addr	Stack 
	//	   			t[3]
	//				t[2]
	//				t[1]
	//		t->		t[0]
	//		...		...
	//		timer	data
	//		timer	data
	//		timer	data
	//		timer	data

	#ifdef debug_print
	printf("timer: 0x%x\n", timer);
	for (int i = 0; i < timer_len; i++){
		printf("t[%d]:0x%hhx ",i, t[i]);
	}
	printf("\n");

	unsigned int temp;
	memcpy(&temp, &timer, timer_len);
	printf("temp:0x%x\n", temp);
	#endif
	
	// 	ipad = the byte 0x36 repeated B times
	//  opad = the byte 0x5C repeated B times.
	//  H(K XOR opad, H(K XOR ipad, text))
	// 	(1) append zeros to the end of K to create a B byte string
	//  	(e.g., if K is of length 20 bytes and B=64, then K will be
	//  	appended with 44 zero bytes 0x00)
	//  (2) XOR (bitwise exclusive-OR) the B byte string computed in step
	//  	(1) with ipad
	//  (3) append the stream of data 'text' to the B byte string resulting
	//  	from step (2)
	//  (4) apply H to the stream generated in step (3)
	//  (5) XOR (bitwise exclusive-OR) the B byte string computed in
	//  	step (1) with opad
	//  (6) append the H result from step (4) to the B byte string
	//  	resulting from step (5)
	//  (7) apply H to the stream generated in step (6) and output
	//  	the result

	char ipad[64], opad[64];
	for (int i = 0; i < 64; i++){
		ipad[i] = '\x36';
		opad[i] = '\x5c';
	}

	//(1) K
	uint8_t * secret_binary;
	int secret_binary_len = hex_to_binary_conversion(secret_hex, &secret_binary);

	uint8_t k[64];
	for (int i = 0; i < 64; i++){
		if (i < secret_binary_len){
			k[i] = secret_binary[i];
		}
		else{
			k[i] = '\x00';
		}
	}

	#ifdef debug_print
	printf("secret_binary: ");
	for (int i = 0; i < secret_binary_len; i++){
		printf("0x%hhx ", secret_binary[i]);
	}
	printf("\n");
	printf("secret_binary_len: %d\n", secret_binary_len);
	#endif
	

	//(2) K XOR ipad
	char k_xor_ipad[64];
	for (int i = 0; i < 64; i++){
		k_xor_ipad[i] = k[i] ^ ipad[i];
	}

	#ifdef debug_print
	printf("k:\n");
	for (int i = 0; i < 64; i++){
		printf("0x%hhx ", k[i]);
	}
	printf("\n");
	printf("ipad:\n");
	for (int i = 0; i < 64; i++){
		printf("0x%hhx ", ipad[i]);
	}
	printf("\n");
	printf("k_xor_ipad:\n");
	for (int i = 0; i < 64; i++){
		printf("0x%hhx ", k_xor_ipad[i]);
	}
	printf("\n");
	#endif

	//(3) K XOR ipad + T
	char k_xor_ipad_and_T[128];
	memcpy(k_xor_ipad_and_T, k_xor_ipad, 64);
	memcpy(k_xor_ipad_and_T+64, t, timer_len);

	#ifdef debug_print
	// //test
	// for (int i = 0; i < 64+timer_len; i++){
	// 	k_xor_ipad_and_T[i] = 0;
	// }
	// k_xor_ipad_and_T[0] = '\x11';
	// //test
	printf("k_xor_ipad_and_T:\n");
	for (int i = 0; i < 64+timer_len; i++){
		printf("%hhx", k_xor_ipad_and_T[i]);
	}
	printf("\n");
	#endif
	
	//(4) H(K XOR ipad + text)
	SHA1_INFO ctx;
	uint8_t sha[SHA1_DIGEST_LENGTH];


	// k_xor_ipad_and_T[0] = '\x26';
	// k_xor_ipad_and_T[1] = '\x24';
	printf("k_xor_ipad_and_T[0]: %hhx\n", k_xor_ipad_and_T[0]);
	printf("k_xor_ipad_and_T[1]: %hhx\n", k_xor_ipad_and_T[1]);


	sha1_init(&ctx);
	sha1_update(&ctx, k_xor_ipad_and_T, 64); //hash 512 bits = 64 bytes, hash twice
	sha1_update(&ctx, k_xor_ipad_and_T+64, timer_len);
	// sha1_update(&ctx, k_xor_ipad_and_T, 64+timer_len); //hash 512 bits = 64 bytes, hash twice
	// sha1_update(&ctx, k_xor_ipad_and_T, 64+timer_len);
	// sha1_update(&ctx, "\x1100000000000000000000000000000000000000000000000000000000000000000000000", 1);
	// keep calling sha1_update if you have more data to hash...
	sha1_final(&ctx, sha);

	#ifdef debug_print
	for (int i = 0; i < SHA1_DIGEST_LENGTH; i++){
		printf("sha[%d]: 0x%x\t", i, sha[i]);
	}
	printf("\n");
	#endif


	//(5) K XOR opad
	uint8_t k_xor_opad[64] = "\0";
	for (int i = 0; i < 64; i++){
		k_xor_opad[i] = k[i] ^ opad[i];
	}

	#ifdef debug_print
	printf("k_xor_opad:\n");
	for (int i = 0; i < 64; i++){
		printf("0x%hhx ", k_xor_opad[i]);
	}
	printf("\n");
	#endif

	//(6) K XOR opad + H(K XOR ipad + text)
	uint8_t k_xor_opad_and_H[128];
	memcpy(k_xor_opad_and_H, k_xor_opad, 64);
	for (int i = 0; i < SHA1_DIGEST_LENGTH; i++){
		memcpy(k_xor_opad_and_H+64+i, sha+i, 1);
	}

	#ifdef debug_print
	printf("k_xor_opad_and_H:\n");
	for (int i = 0; i < 64+SHA1_DIGEST_LENGTH; i++){
		printf("0x%hhx ", k_xor_opad_and_H[i]);
	}
	printf("\n");
	#endif

	//(7) H(K XOR opad + H(K XOR ipad + text))
	SHA1_INFO ctx1;
	uint8_t sha1[SHA1_DIGEST_LENGTH];

	for (int i = 0; i < SHA1_DIGEST_LENGTH; i++){
		sha1[i] = 0;
	}

	sha1_init(&ctx1);
	sha1_update(&ctx1, k_xor_opad_and_H, 64); //hash 512 bits = 64 bytes, hash twice
	sha1_update(&ctx1, k_xor_opad_and_H+64, SHA1_DIGEST_LENGTH);
	// keep calling sha1_update if you have more data to hash...
	sha1_final(&ctx1, sha1);

	#ifdef debug_print
	for (int i = 0; i < SHA1_DIGEST_LENGTH; i++){
		printf("sha1[%d]: 0x%x\t", i, sha1[i]);
	}
	printf("\n");
	#endif


	//HOTP(K,C) = Truncate(HMAC-SHA-1(K,C))
	// 	Step 1: Generate an HMAC-SHA-1 value Let HS = HMAC-SHA-1(K,C) // HS
	//  is a 20-byte string
	//  Step 2: Generate a 4-byte string (Dynamic Truncation)
	//  Let Sbits = DT(HS) // DT, defined below,
	//  // returns a 31-bit string
	//  Step 3: Compute an HOTP value
	//  Let Snum = StToNum(Sbits) // Convert S to a number in
	//  0...2^{31}-1
	//  Return D = Snum mod 10^Digit // D is a number in the range
	//  0...10^{Digit}-1

	// 	DT(String) // String = String[0]...String[19]
	//  Let OffsetBits be the low-order 4 bits of String[19]
	//  Offset = StToNum(OffsetBits) // 0 <= OffSet <= 15
	//  Let P = String[OffSet]...String[OffSet+3]
	//  Return the Last 31 bits of P


	//step 1
	uint8_t HS[SHA1_DIGEST_LENGTH];
	memcpy(HS, sha1, SHA1_DIGEST_LENGTH);

	//step 2
	uint8_t Sbits[4];

	//offset is the lower 4 bits of HS[19]
	uint8_t offset = HS[19] & 0b00001111;

	printf("HS[19]: %hhx, offset: %hhx\n", HS[19], offset);
	
	memcpy(Sbits, &(HS[offset+3]), 1);
	memcpy(Sbits+1, &(HS[offset+2]), 1);
	memcpy(Sbits+2, &(HS[offset+1]), 1);
	memcpy(Sbits+3, &(HS[offset]), 1);

	Sbits[3] = Sbits[3] & 0x7f;  //take the lower 31 bits

	for(int i = 0; i < 4; i++){
		printf("Sbits[%d]: %hhx  ", i, Sbits[i]);
	}
	printf("\n");

	//step 3
	//covert Sbits to a int
	unsigned int Snum;
	memcpy(&Snum, Sbits, 4);

	printf("Snum = %x\n", Snum);

	//D = Snum mod 10^Digit
	unsigned int TOTP_Calculated = Snum % (10*10*10*10*10*10-1);

	printf("TOTP_Calculated: %d\n", TOTP_Calculated);

	//TOTP_string ---> TOTP_input
	unsigned int TOTP_input;
	TOTP_input = atoi(TOTP_string);

	printf("TOTP_input: %.6d\n", TOTP_input);

	if (TOTP_Calculated == TOTP_input){
		return (1);
	}
	else{
		return(0);
	}
}


int
main(int argc, char * argv[])
{
	if ( argc != 3 ) {
		printf("Usage: %s [secretHex] [TOTP]\n", argv[0]);
		return(-1);
	}

	char *	secret_hex = argv[1];
	char *	TOTP_value = argv[2];

	assert (strlen(secret_hex) <= 20);
	assert (strlen(TOTP_value) == 6);

	printf("\nSecret (Hex): %s\nTOTP Value: %s (%s)\n\n",
		secret_hex,
		TOTP_value,
		validateTOTP(secret_hex, TOTP_value) ? "valid" : "invalid");

	return(0);
}

int hex_to_binary_conversion(char * hex, uint8_t ** binary_result){
	int hex_length = strlen(hex);
	if (hex_length<=0){
		printf("Invalid hex number length: %d\n", hex_length);
		return 0;
	}

	//allocate binary
	int binary_length = hex_length/2;//binary length = hex_length*4
	*binary_result = malloc(sizeof(uint8_t)*binary_length); 
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
			return 0;
			break;
		}

		if (i%2 == 1){
			(*binary_result)[i/2] = last_digit*16+digit;
		}

		last_digit = digit;

	}
	
	// printf("here\n");

	return binary_length;
}