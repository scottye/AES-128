#include "AES_128.h"

//====================================================================

unsigned char StateArray[4][4];
unsigned char ExpandedKey[11][4][4];
//								  W0	W1	  W2	W3
unsigned char Key[4][4]		={	{0x2b, 0x28, 0xab, 0x09},
								{0x7e, 0xae, 0xf7, 0xcf},
								{0x15, 0xd2, 0x15, 0x4f},
								{0x16, 0xa6, 0x88, 0x3c}};

//								  W0	W1	  W2	W3
unsigned char PlainText[4][4]={{0x32, 0x88, 0x31, 0xe0},
								{0x43, 0x5a, 0x31, 0x37},
								{0xf6, 0x30, 0x98, 0x07},
								{0xa8, 0x8d, 0xa2, 0x34}};								

//unsigned char PlainText[4][4]={{0x6b, 0x2e, 0xe9, 0x73},
//								{0xc1, 0x40, 0x3d, 0x93},
//								{0xbe, 0x9f, 0x7e, 0x17},
//								{0xe2, 0x96, 0x11, 0x2a}};

// To set all bytes in a block of memory to a particular value,
// use void * memset(void *dest, int c, size_t count). 							

unsigned int T0[256];
unsigned int T1[256];
unsigned int T2[256];
unsigned int T3[256];

void encrypt();
void decrypt();
								
int main (void) {
	printf("\n\n\n");
	printf("-- Strarting AES software test based on FIPS-197 \
	(Appendix B)\r\n\n");
	
	//-----------------------------------------
	//--------Encrypt Function-----------------
	//-----------------------------------------
	
	encrypt();
	
	//-----------------------------------------
	//--------Decrypt Function-----------------
	//-----------------------------------------
	
	//decrypt();
	
	//-----------------------------------------
	//--------Display Results------------------
	//-----------------------------------------
	
	printf("***************************************************\r\n");
	
	printf("-- Exiting main() --\r\n");
	//cleanup_platform();
	
	return 0;
}

void encrypt() {
	bzero(StateArray, 4*4*sizeof(unsigned char));
	
	bzero(ExpandedKey, 11*4*4*sizeof(unsigned char));

#if (AES_PRINT & AES_PRINT_MAIN)
	printf("-- Test Encryption Key \r\n\n");
	AES_printf(Key);
	printf("-----------------------\r\n\n");
	
	printf("-- Test Plaintext \r\n\n");
	AES_printf(PlainText);
	printf("-----------------------\r\n\n");
#endif

#if (AES_PRINT & AES_PRINT_MAIN)
	printf("-- Starting Key Expansion \r\n\n");
#endif

	ExpandKey(Key, ExpandedKey);
	
#if (AES_PRINT & AES_PRINT_MAIN)
	printf("-- Starting Encryption \r\n\n");
#endif
	
	long int x;
	for(x=0; x<1; x++) {
		memcpy(StateArray, PlainText, 4 * 4 * sizeof(unsigned char));
		
#if (AES_PRINT & AES_PRINT_DETAILS)
		printf("-- Test State - Start of Round 0 \r\n\n");
		AES_printf(StateArray);
		printf("-----------------------\r\n\n");
#endif

		AddRoundKey(ExpandedKey[0], StateArray);
#if (AES_PRINT & AES_PRINT_DETAILS)
		printf("-- Test State - End of Round 0 \r\n\n");
		AES_printf(StateArray);
		printf("-----------------------\r\n\n");
#endif

		int i;
		
		// Rounds
		for(i=1; i<=10; i++) {
			if(i != 10) {
			  AESRound(StateArray, ExpandedKey[i]);
#if (AES_PRINT & AES_PRINT_DETAILS)
				printf("-- Test State - Round %d after AESRound \r\n\n",i);
				AES_printf(StateArray);
				printf("-----------------------\r\n\n");
#endif			
			} else {
			  SubBytes(StateArray);
			  ShiftRows(StateArray);
#if (AES_PRINT & AES_PRINT_DETAILS)
			  printf("-- Test State - After SubBytesShiftRows \r\n\n");
			  AES_printf(StateArray);
			  printf("-----------------------\r\n\n");
#endif
			  AddRoundKey(ExpandedKey[i], StateArray);
#if (AES_PRINT & AES_PRINT_DETAILS)
			  printf("-- Test State - After SubBytesShiftRows \r\n\n");
			  AES_printf(StateArray);
			  printf("-----------------------\r\n\n");
#endif
			}
		}
	}
#if (AES_PRINT & AES_PRINT_DETAILS)
	printf("-- AES key expansion and encryption test completed. \r\n\n");
	printf("-- Test State - End \r\n\n");
	AES_printf(StateArray);
	printf("-----------------------\r\n\n");
#endif
}

void decrypt() {
	unsigned char Ciphertext[4][4];
	memcpy(Ciphertext, StateArray, 4 * 4 * sizeof(unsigned char));
#if (AES_PRINT & AES_PRINT_MAIN)
	printf("-- Starting Decryption \r\n\n");
#endif

	//TODO: Our Code here
	
#if (AES_PRINT & AES_PRINT_MAIN)
	printf("-- Test Encryption Key \r\n\n");
	AES_printf(Key);
	printf("-----------------------\r\n\n");
	
	printf("-- Test Ciphertext \r\n\n");
	AES_printf(Ciphertext);
	printf("-----------------------\r\n\n");
#endif

#if (AES_PRINT & AES_PRINT_MAIN)
	printf("-- Starting Decryption \r\n\n");
#endif
	
	long int x;
	for(x=0; x<1; x++) {
		memcpy(StateArray, Ciphertext, 4 * 4 * sizeof(unsigned char));
		
#if (AES_PRINT & AES_PRINT_DETAILS)
		printf("-- Test State - Start of Round 10 \r\n\n");
		AES_printf(StateArray);
		printf("-----------------------\r\n\n");
#endif

		AddRoundKey(ExpandedKey[10], StateArray);
#if (AES_PRINT & AES_PRINT_DETAILS)
		printf("-- Test State - End of Round 10 after AddRoundKey\r\n\n");
		AES_printf(StateArray);
		printf("-----------------------\r\n\n");
#endif

		// Rounds
		int i;
		for(i=9; i>=0; i--) {
			InvShiftRows(StateArray);
#if (AES_PRINT & AES_PRINT_DETAILS)
			printf("-- Test State- Round %d after InvShiftRows \r\n\n",i);
			AES_printf(StateArray);
			printf("-----------------------\r\n\n");
#endif

			InvSubBytesCalculated(StateArray);
#if (AES_PRINT & AES_PRINT_DETAILS)
			printf("-- Test State - Round %d after InvSubBytes \r\n\n",i);
			AES_printf(StateArray);
			printf("-----------------------\r\n\n");
#endif			

			AddRoundKey(ExpandedKey[i], StateArray);
#if (AES_PRINT & AES_PRINT_DETAILS)
			printf("-- Test State - Round %d after AddRoundKey\r\n\n", i);
			AES_printf(StateArray);
			printf("-----------------------\r\n\n");
#endif

			if(i != 0) {
				InvMixColumns(StateArray);
#if (AES_PRINT & AES_PRINT_DETAILS)
				printf("-- Test State - End of round %d after InvMixColumns \r\n\n",i);
				AES_printf(StateArray);
				printf("-----------------------\r\n\n");
#endif			
			}
			
		}
	}
#if (AES_PRINT & AES_PRINT_DETAILS)
	printf("-- AES decryption test completed. \r\n\n");
	printf("-- Test State - End \r\n\n");
	AES_printf(StateArray);
	printf("-----------------------\r\n\n");
#endif





}
