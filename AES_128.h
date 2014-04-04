#ifndef AES_128_H_
#define AES_128_H_

#include "stdio.h"
#include "string.h"
#include "stdlib.h"

//#define printf xil_printf

/**
 * Debug levels
 */
 
#define AES_PRINT_MAIN		(1<<0)
#define AES_PRINT_DETAILS	(1<<1)
 
#define AES_PRINT (AES_PRINT_MAIN | AES_PRINT_DETAILS)
 
 /***********************************************************************
  * Functions for key expansion
  **********************************************************************/
  
 void ExpandKey(unsigned char Key[][4], unsigned char ExpandedKey[][4][4]);
 void AddRoundKey(unsigned char Key[][4], unsigned char StateArray[][4]);
  
 /***********************************************************************
  * Functions for AES encryption
  **********************************************************************/
 
void SubBytes(unsigned char StateArray[][4]);
void ShiftRows(unsigned char StateArray[][4]);

void FillTBoxes(void);
void AESRound(unsigned char StateArray[][4], unsigned char ExpandedKey[][4]);
 
 /***********************************************************************
  * Functions for AES decryption
  **********************************************************************/

void InvSubBytes(unsigned char StateArray[][4]);
void InvShiftRows(unsigned char StateArray[][4]);
void InvMixColumns(unsigned char StateArray[][4]);

 /***********************************************************************
  * Miscellaneous Functions
  **********************************************************************/

void AES_printf(unsigned char StateArray[][4]);


#endif /* AES_128_H_ */  
