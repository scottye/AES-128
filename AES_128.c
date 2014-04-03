#include "AES_128.h"

const unsigned char SBox[256] = {
 // 0     1     2     3     4     5     6     7     8     9     A     B     C     D     E     F
 0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,   //0
 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,   //1
 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,   //2
 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,   //3
 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,   //4
 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,   //5
 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,   //6
 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,   //7
 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,   //8
 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,   //9
 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,   //A
 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,   //B
 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,   //C
 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,   //D
 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,   //E
 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 }; //F

const unsigned char invSBox[256] = {
   // 0		1	  2		3	  4		5	  6		7	  8		9	  A		B	  C		D	  E		F
   0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,	//0
   0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,  //1
   0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,  //2
   0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,  //3
   0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,  //4
   0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,  //5
   0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,  //6
   0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,  //7
   0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,  //8
   0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,  //9
   0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,  //A
   0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,  //B
   0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,  //C
   0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,  //D
   0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,  //E
   0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D}; //F
const unsigned char invSBox[256];

const unsigned char RCon[10] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x020, 0x40, 0x80, 0x1b, 0x36};

#define xTime(x) ((x<<1) ^ ((x & 0x080) ? 0x1b : 0x00))
#define FX 0x11b 	//irreducible polynomial used
#define DEGREE 8	//degree of the field
#define MSB 0x80	//msb of a reduced element
#define GPB 0x100

unsigned char multiply(unsigned char a, unsigned char b) {
	unsigned char result = 0;
	unsigned char temp,temp2  = 0;
	unsigned char mask = 1;
	char i = 0;
	
	temp = a; //initialize temp a scrubbed a


	if (a == 0 || b == 0) return 0;

	// Iteration 0
	if (b & mask)
		result = temp ^ result;
	temp2 = temp;
	temp = temp << 1;
	if (temp2 & MSB)
		temp = temp ^ FX;
	mask = mask << 1;
	// Iteration 1
	if (b & mask)
		result = temp ^ result;
	temp2 = temp;
	temp = temp << 1;
	if (temp2 & MSB)
		temp = temp ^ FX;
	mask = mask << 1;
	// Iteration 2
	if (b & mask)
		result = temp ^ result;
	temp2 = temp;
	temp = temp << 1;
	if (temp2 & MSB)
		temp = temp ^ FX;
	mask = mask << 1;
	// Iteration 3
	if (b & mask)
		result = temp ^ result;
	temp2 = temp;
	temp = temp << 1;
	if (temp2 & MSB)
		temp = temp ^ FX;
	mask = mask << 1;
	// Iteration 4
	if (b & mask)
		result = temp ^ result;
	temp2 = temp;
	temp = temp << 1;
	if (temp2 & MSB)
		temp = temp ^ FX;
	mask = mask << 1;
	// Iteration 5
	if (b & mask)
		result = temp ^ result;
	temp2 = temp;
	temp = temp << 1;
	if (temp2 & MSB)
		temp = temp ^ FX;
	mask = mask << 1;
	// Iteration 6
	if (b & mask)
		result = temp ^ result;
	temp2 = temp;
	temp = temp << 1;
	if (temp2 & MSB)
		temp = temp ^ FX;
	mask = mask << 1;
	// Iteration 7
	if (b & mask)
		result = temp ^ result;

	return result;
}

unsigned int divide (unsigned int a, unsigned int b)
{
  unsigned int temp, rem, div_msb, result, c;

  if (b > a)
    return (a ^ b);

  if (b == a)
    return 1;

  result = 0;
  rem = a;
  while (rem > b)
    {
      c = 0x01;
      temp = b;

      //Due to GF8 msb possible is 0x100
	  div_msb = 0x100;
      while (((div_msb & rem) || (div_msb & temp)) == 0)
	    div_msb >>= 1;
      while ((div_msb & temp) == 0)
	{
	  temp <<= 1;
	  c <<= 1;
	}

      result = result + c;
      rem = rem ^ temp;
    }

  return result;
}

unsigned int ee(unsigned int a, unsigned int b)
{
  //Reduce input to one degree less an fx
  if (a & GPB) {
    a = a ^ FX;
  }
  unsigned int u = 0;
  unsigned int u_n = 1;
  unsigned int r = b;
  unsigned int r_n = a;
  unsigned int q, t;

  while (r_n != 0)
    {
      q = divide(r, r_n);

      t = r_n;
      r_n = r ^ multiply(q, r_n);

	  //Reduce if result is same degree as FX
	  if(r_n & GPB) {
	    r_n = r_n ^ FX;
	  }
      r = t;

      t = u_n;
      u_n = u ^ multiply(q, u_n);

	  //Reduce if result is same degree as FX
	  if(u_n & GPB) {
	    u_n = u_n ^ FX;
	  }
      u = t;
    }

  return u;
}

void ExpandKey (unsigned char Key[][4], unsigned char ExpandedKey[][4][4])
{
  unsigned char TempKey[4][4];
  bzero (TempKey, 4*4*sizeof (unsigned char));
  unsigned char TempKeyCol[4];
  bzero (TempKeyCol, 4*sizeof (unsigned char));
  int i, j;

  memcpy (ExpandedKey[0], Key, 4*4*sizeof (unsigned char));

  // Outer iteration 1
  TempKeyCol[0] = ExpandedKey[1-1][1][3];
  TempKeyCol[1] = ExpandedKey[1-1][2][3];
  TempKeyCol[2] = ExpandedKey[1-1][3][3];
  TempKeyCol[3] = ExpandedKey[1-1][0][3];
  TempKeyCol[0] = SBox[ TempKeyCol[0] ];
  TempKeyCol[1] = SBox[ TempKeyCol[1] ];
  TempKeyCol[2] = SBox[ TempKeyCol[2] ];
  TempKeyCol[3] = SBox[ TempKeyCol[3] ];
  TempKeyCol[0] ^= RCon[1-1];
  // Iteration 0
  TempKeyCol[0] = TempKeyCol[0] ^ ExpandedKey[1-1][0][0];
  TempKeyCol[1] = TempKeyCol[1] ^ ExpandedKey[1-1][1][0];
  TempKeyCol[2] = TempKeyCol[2] ^ ExpandedKey[1-1][2][0];
  TempKeyCol[3] = TempKeyCol[3] ^ ExpandedKey[1-1][3][0];
  ExpandedKey[1][0][0] = TempKeyCol[0];
  ExpandedKey[1][1][0] = TempKeyCol[1];
  ExpandedKey[1][2][0] = TempKeyCol[2];
  ExpandedKey[1][3][0] = TempKeyCol[3];
  // Iteration 1
  TempKeyCol[0] = TempKeyCol[0] ^ ExpandedKey[1-1][0][1];
  TempKeyCol[1] = TempKeyCol[1] ^ ExpandedKey[1-1][1][1];
  TempKeyCol[2] = TempKeyCol[2] ^ ExpandedKey[1-1][2][1];
  TempKeyCol[3] = TempKeyCol[3] ^ ExpandedKey[1-1][3][1];
  ExpandedKey[1][0][1] = TempKeyCol[0];
  ExpandedKey[1][1][1] = TempKeyCol[1];
  ExpandedKey[1][2][1] = TempKeyCol[2];
  ExpandedKey[1][3][1] = TempKeyCol[3];
  // Iteration 2
  TempKeyCol[0] = TempKeyCol[0] ^ ExpandedKey[1-1][0][2];
  TempKeyCol[1] = TempKeyCol[1] ^ ExpandedKey[1-1][1][2];
  TempKeyCol[2] = TempKeyCol[2] ^ ExpandedKey[1-1][2][2];
  TempKeyCol[3] = TempKeyCol[3] ^ ExpandedKey[1-1][3][2];
  ExpandedKey[1][0][2] = TempKeyCol[0];
  ExpandedKey[1][1][2] = TempKeyCol[1];
  ExpandedKey[1][2][2] = TempKeyCol[2];
  ExpandedKey[1][3][2] = TempKeyCol[3];
  // Iteration 3
  TempKeyCol[0] = TempKeyCol[0] ^ ExpandedKey[1-1][0][3];
  TempKeyCol[1] = TempKeyCol[1] ^ ExpandedKey[1-1][1][3];
  TempKeyCol[2] = TempKeyCol[2] ^ ExpandedKey[1-1][2][3];
  TempKeyCol[3] = TempKeyCol[3] ^ ExpandedKey[1-1][3][3];
  ExpandedKey[1][0][3] = TempKeyCol[0];
  ExpandedKey[1][1][3] = TempKeyCol[1];
  ExpandedKey[1][2][3] = TempKeyCol[2];
  ExpandedKey[1][3][3] = TempKeyCol[3];
  // Outer iteration 2
  TempKeyCol[0] = ExpandedKey[2-1][1][3];
  TempKeyCol[1] = ExpandedKey[2-1][2][3];
  TempKeyCol[2] = ExpandedKey[2-1][3][3];
  TempKeyCol[3] = ExpandedKey[2-1][0][3];
  TempKeyCol[0] = SBox[ TempKeyCol[0] ];
  TempKeyCol[1] = SBox[ TempKeyCol[1] ];
  TempKeyCol[2] = SBox[ TempKeyCol[2] ];
  TempKeyCol[3] = SBox[ TempKeyCol[3] ];
  TempKeyCol[0] ^= RCon[2-1];
  // Iteration 0
  TempKeyCol[0] = TempKeyCol[0] ^ ExpandedKey[2-1][0][0];
  TempKeyCol[1] = TempKeyCol[1] ^ ExpandedKey[2-1][1][0];
  TempKeyCol[2] = TempKeyCol[2] ^ ExpandedKey[2-1][2][0];
  TempKeyCol[3] = TempKeyCol[3] ^ ExpandedKey[2-1][3][0];
  ExpandedKey[2][0][0] = TempKeyCol[0];
  ExpandedKey[2][1][0] = TempKeyCol[1];
  ExpandedKey[2][2][0] = TempKeyCol[2];
  ExpandedKey[2][3][0] = TempKeyCol[3];
  // Iteration 1
  TempKeyCol[0] = TempKeyCol[0] ^ ExpandedKey[2-1][0][1];
  TempKeyCol[1] = TempKeyCol[1] ^ ExpandedKey[2-1][1][1];
  TempKeyCol[2] = TempKeyCol[2] ^ ExpandedKey[2-1][2][1];
  TempKeyCol[3] = TempKeyCol[3] ^ ExpandedKey[2-1][3][1];
  ExpandedKey[2][0][1] = TempKeyCol[0];
  ExpandedKey[2][1][1] = TempKeyCol[1];
  ExpandedKey[2][2][1] = TempKeyCol[2];
  ExpandedKey[2][3][1] = TempKeyCol[3];
  // Iteration 2
  TempKeyCol[0] = TempKeyCol[0] ^ ExpandedKey[2-1][0][2];
  TempKeyCol[1] = TempKeyCol[1] ^ ExpandedKey[2-1][1][2];
  TempKeyCol[2] = TempKeyCol[2] ^ ExpandedKey[2-1][2][2];
  TempKeyCol[3] = TempKeyCol[3] ^ ExpandedKey[2-1][3][2];
  ExpandedKey[2][0][2] = TempKeyCol[0];
  ExpandedKey[2][1][2] = TempKeyCol[1];
  ExpandedKey[2][2][2] = TempKeyCol[2];
  ExpandedKey[2][3][2] = TempKeyCol[3];
  // Iteration 3
  TempKeyCol[0] = TempKeyCol[0] ^ ExpandedKey[2-1][0][3];
  TempKeyCol[1] = TempKeyCol[1] ^ ExpandedKey[2-1][1][3];
  TempKeyCol[2] = TempKeyCol[2] ^ ExpandedKey[2-1][2][3];
  TempKeyCol[3] = TempKeyCol[3] ^ ExpandedKey[2-1][3][3];
  ExpandedKey[2][0][3] = TempKeyCol[0];
  ExpandedKey[2][1][3] = TempKeyCol[1];
  ExpandedKey[2][2][3] = TempKeyCol[2];
  ExpandedKey[2][3][3] = TempKeyCol[3];
  // Outer iteration 3
  TempKeyCol[0] = ExpandedKey[3-1][1][3];
  TempKeyCol[1] = ExpandedKey[3-1][2][3];
  TempKeyCol[2] = ExpandedKey[3-1][3][3];
  TempKeyCol[3] = ExpandedKey[3-1][0][3];
  TempKeyCol[0] = SBox[ TempKeyCol[0] ];
  TempKeyCol[1] = SBox[ TempKeyCol[1] ];
  TempKeyCol[2] = SBox[ TempKeyCol[2] ];
  TempKeyCol[3] = SBox[ TempKeyCol[3] ];
  TempKeyCol[0] ^= RCon[3-1];
  // Iteration 0
  TempKeyCol[0] = TempKeyCol[0] ^ ExpandedKey[3-1][0][0];
  TempKeyCol[1] = TempKeyCol[1] ^ ExpandedKey[3-1][1][0];
  TempKeyCol[2] = TempKeyCol[2] ^ ExpandedKey[3-1][2][0];
  TempKeyCol[3] = TempKeyCol[3] ^ ExpandedKey[3-1][3][0];
  ExpandedKey[3][0][0] = TempKeyCol[0];
  ExpandedKey[3][1][0] = TempKeyCol[1];
  ExpandedKey[3][2][0] = TempKeyCol[2];
  ExpandedKey[3][3][0] = TempKeyCol[3];
  // Iteration 1
  TempKeyCol[0] = TempKeyCol[0] ^ ExpandedKey[3-1][0][1];
  TempKeyCol[1] = TempKeyCol[1] ^ ExpandedKey[3-1][1][1];
  TempKeyCol[2] = TempKeyCol[2] ^ ExpandedKey[3-1][2][1];
  TempKeyCol[3] = TempKeyCol[3] ^ ExpandedKey[3-1][3][1];
  ExpandedKey[3][0][1] = TempKeyCol[0];
  ExpandedKey[3][1][1] = TempKeyCol[1];
  ExpandedKey[3][2][1] = TempKeyCol[2];
  ExpandedKey[3][3][1] = TempKeyCol[3];
  // Iteration 2
  TempKeyCol[0] = TempKeyCol[0] ^ ExpandedKey[3-1][0][2];
  TempKeyCol[1] = TempKeyCol[1] ^ ExpandedKey[3-1][1][2];
  TempKeyCol[2] = TempKeyCol[2] ^ ExpandedKey[3-1][2][2];
  TempKeyCol[3] = TempKeyCol[3] ^ ExpandedKey[3-1][3][2];
  ExpandedKey[3][0][2] = TempKeyCol[0];
  ExpandedKey[3][1][2] = TempKeyCol[1];
  ExpandedKey[3][2][2] = TempKeyCol[2];
  ExpandedKey[3][3][2] = TempKeyCol[3];
  // Iteration 3
  TempKeyCol[0] = TempKeyCol[0] ^ ExpandedKey[3-1][0][3];
  TempKeyCol[1] = TempKeyCol[1] ^ ExpandedKey[3-1][1][3];
  TempKeyCol[2] = TempKeyCol[2] ^ ExpandedKey[3-1][2][3];
  TempKeyCol[3] = TempKeyCol[3] ^ ExpandedKey[3-1][3][3];
  ExpandedKey[3][0][3] = TempKeyCol[0];
  ExpandedKey[3][1][3] = TempKeyCol[1];
  ExpandedKey[3][2][3] = TempKeyCol[2];
  ExpandedKey[3][3][3] = TempKeyCol[3];
  // Outer iteration 4
  TempKeyCol[0] = ExpandedKey[4-1][1][3];
  TempKeyCol[1] = ExpandedKey[4-1][2][3];
  TempKeyCol[2] = ExpandedKey[4-1][3][3];
  TempKeyCol[3] = ExpandedKey[4-1][0][3];
  TempKeyCol[0] = SBox[ TempKeyCol[0] ];
  TempKeyCol[1] = SBox[ TempKeyCol[1] ];
  TempKeyCol[2] = SBox[ TempKeyCol[2] ];
  TempKeyCol[3] = SBox[ TempKeyCol[3] ];
  TempKeyCol[0] ^= RCon[4-1];
  // Iteration 0
  TempKeyCol[0] = TempKeyCol[0] ^ ExpandedKey[4-1][0][0];
  TempKeyCol[1] = TempKeyCol[1] ^ ExpandedKey[4-1][1][0];
  TempKeyCol[2] = TempKeyCol[2] ^ ExpandedKey[4-1][2][0];
  TempKeyCol[3] = TempKeyCol[3] ^ ExpandedKey[4-1][3][0];
  ExpandedKey[4][0][0] = TempKeyCol[0];
  ExpandedKey[4][1][0] = TempKeyCol[1];
  ExpandedKey[4][2][0] = TempKeyCol[2];
  ExpandedKey[4][3][0] = TempKeyCol[3];
  // Iteration 1
  TempKeyCol[0] = TempKeyCol[0] ^ ExpandedKey[4-1][0][1];
  TempKeyCol[1] = TempKeyCol[1] ^ ExpandedKey[4-1][1][1];
  TempKeyCol[2] = TempKeyCol[2] ^ ExpandedKey[4-1][2][1];
  TempKeyCol[3] = TempKeyCol[3] ^ ExpandedKey[4-1][3][1];
  ExpandedKey[4][0][1] = TempKeyCol[0];
  ExpandedKey[4][1][1] = TempKeyCol[1];
  ExpandedKey[4][2][1] = TempKeyCol[2];
  ExpandedKey[4][3][1] = TempKeyCol[3];
  // Iteration 2
  TempKeyCol[0] = TempKeyCol[0] ^ ExpandedKey[4-1][0][2];
  TempKeyCol[1] = TempKeyCol[1] ^ ExpandedKey[4-1][1][2];
  TempKeyCol[2] = TempKeyCol[2] ^ ExpandedKey[4-1][2][2];
  TempKeyCol[3] = TempKeyCol[3] ^ ExpandedKey[4-1][3][2];
  ExpandedKey[4][0][2] = TempKeyCol[0];
  ExpandedKey[4][1][2] = TempKeyCol[1];
  ExpandedKey[4][2][2] = TempKeyCol[2];
  ExpandedKey[4][3][2] = TempKeyCol[3];
  // Iteration 3
  TempKeyCol[0] = TempKeyCol[0] ^ ExpandedKey[4-1][0][3];
  TempKeyCol[1] = TempKeyCol[1] ^ ExpandedKey[4-1][1][3];
  TempKeyCol[2] = TempKeyCol[2] ^ ExpandedKey[4-1][2][3];
  TempKeyCol[3] = TempKeyCol[3] ^ ExpandedKey[4-1][3][3];
  ExpandedKey[4][0][3] = TempKeyCol[0];
  ExpandedKey[4][1][3] = TempKeyCol[1];
  ExpandedKey[4][2][3] = TempKeyCol[2];
  ExpandedKey[4][3][3] = TempKeyCol[3];
  // Outer iteration 5
  TempKeyCol[0] = ExpandedKey[5-1][1][3];
  TempKeyCol[1] = ExpandedKey[5-1][2][3];
  TempKeyCol[2] = ExpandedKey[5-1][3][3];
  TempKeyCol[3] = ExpandedKey[5-1][0][3];
  TempKeyCol[0] = SBox[ TempKeyCol[0] ];
  TempKeyCol[1] = SBox[ TempKeyCol[1] ];
  TempKeyCol[2] = SBox[ TempKeyCol[2] ];
  TempKeyCol[3] = SBox[ TempKeyCol[3] ];
  TempKeyCol[0] ^= RCon[5-1];
  // Iteration 0
  TempKeyCol[0] = TempKeyCol[0] ^ ExpandedKey[5-1][0][0];
  TempKeyCol[1] = TempKeyCol[1] ^ ExpandedKey[5-1][1][0];
  TempKeyCol[2] = TempKeyCol[2] ^ ExpandedKey[5-1][2][0];
  TempKeyCol[3] = TempKeyCol[3] ^ ExpandedKey[5-1][3][0];
  ExpandedKey[5][0][0] = TempKeyCol[0];
  ExpandedKey[5][1][0] = TempKeyCol[1];
  ExpandedKey[5][2][0] = TempKeyCol[2];
  ExpandedKey[5][3][0] = TempKeyCol[3];
  // Iteration 1
  TempKeyCol[0] = TempKeyCol[0] ^ ExpandedKey[5-1][0][1];
  TempKeyCol[1] = TempKeyCol[1] ^ ExpandedKey[5-1][1][1];
  TempKeyCol[2] = TempKeyCol[2] ^ ExpandedKey[5-1][2][1];
  TempKeyCol[3] = TempKeyCol[3] ^ ExpandedKey[5-1][3][1];
  ExpandedKey[5][0][1] = TempKeyCol[0];
  ExpandedKey[5][1][1] = TempKeyCol[1];
  ExpandedKey[5][2][1] = TempKeyCol[2];
  ExpandedKey[5][3][1] = TempKeyCol[3];
  // Iteration 2
  TempKeyCol[0] = TempKeyCol[0] ^ ExpandedKey[5-1][0][2];
  TempKeyCol[1] = TempKeyCol[1] ^ ExpandedKey[5-1][1][2];
  TempKeyCol[2] = TempKeyCol[2] ^ ExpandedKey[5-1][2][2];
  TempKeyCol[3] = TempKeyCol[3] ^ ExpandedKey[5-1][3][2];
  ExpandedKey[5][0][2] = TempKeyCol[0];
  ExpandedKey[5][1][2] = TempKeyCol[1];
  ExpandedKey[5][2][2] = TempKeyCol[2];
  ExpandedKey[5][3][2] = TempKeyCol[3];
  // Iteration 3
  TempKeyCol[0] = TempKeyCol[0] ^ ExpandedKey[5-1][0][3];
  TempKeyCol[1] = TempKeyCol[1] ^ ExpandedKey[5-1][1][3];
  TempKeyCol[2] = TempKeyCol[2] ^ ExpandedKey[5-1][2][3];
  TempKeyCol[3] = TempKeyCol[3] ^ ExpandedKey[5-1][3][3];
  ExpandedKey[5][0][3] = TempKeyCol[0];
  ExpandedKey[5][1][3] = TempKeyCol[1];
  ExpandedKey[5][2][3] = TempKeyCol[2];
  ExpandedKey[5][3][3] = TempKeyCol[3];
  // Outer iteration 6
  TempKeyCol[0] = ExpandedKey[6-1][1][3];
  TempKeyCol[1] = ExpandedKey[6-1][2][3];
  TempKeyCol[2] = ExpandedKey[6-1][3][3];
  TempKeyCol[3] = ExpandedKey[6-1][0][3];
  TempKeyCol[0] = SBox[ TempKeyCol[0] ];
  TempKeyCol[1] = SBox[ TempKeyCol[1] ];
  TempKeyCol[2] = SBox[ TempKeyCol[2] ];
  TempKeyCol[3] = SBox[ TempKeyCol[3] ];
  TempKeyCol[0] ^= RCon[6-1];
  // Iteration 0
  TempKeyCol[0] = TempKeyCol[0] ^ ExpandedKey[6-1][0][0];
  TempKeyCol[1] = TempKeyCol[1] ^ ExpandedKey[6-1][1][0];
  TempKeyCol[2] = TempKeyCol[2] ^ ExpandedKey[6-1][2][0];
  TempKeyCol[3] = TempKeyCol[3] ^ ExpandedKey[6-1][3][0];
  ExpandedKey[6][0][0] = TempKeyCol[0];
  ExpandedKey[6][1][0] = TempKeyCol[1];
  ExpandedKey[6][2][0] = TempKeyCol[2];
  ExpandedKey[6][3][0] = TempKeyCol[3];
  // Iteration 1
  TempKeyCol[0] = TempKeyCol[0] ^ ExpandedKey[6-1][0][1];
  TempKeyCol[1] = TempKeyCol[1] ^ ExpandedKey[6-1][1][1];
  TempKeyCol[2] = TempKeyCol[2] ^ ExpandedKey[6-1][2][1];
  TempKeyCol[3] = TempKeyCol[3] ^ ExpandedKey[6-1][3][1];
  ExpandedKey[6][0][1] = TempKeyCol[0];
  ExpandedKey[6][1][1] = TempKeyCol[1];
  ExpandedKey[6][2][1] = TempKeyCol[2];
  ExpandedKey[6][3][1] = TempKeyCol[3];
  // Iteration 2
  TempKeyCol[0] = TempKeyCol[0] ^ ExpandedKey[6-1][0][2];
  TempKeyCol[1] = TempKeyCol[1] ^ ExpandedKey[6-1][1][2];
  TempKeyCol[2] = TempKeyCol[2] ^ ExpandedKey[6-1][2][2];
  TempKeyCol[3] = TempKeyCol[3] ^ ExpandedKey[6-1][3][2];
  ExpandedKey[6][0][2] = TempKeyCol[0];
  ExpandedKey[6][1][2] = TempKeyCol[1];
  ExpandedKey[6][2][2] = TempKeyCol[2];
  ExpandedKey[6][3][2] = TempKeyCol[3];
  // Iteration 3
  TempKeyCol[0] = TempKeyCol[0] ^ ExpandedKey[6-1][0][3];
  TempKeyCol[1] = TempKeyCol[1] ^ ExpandedKey[6-1][1][3];
  TempKeyCol[2] = TempKeyCol[2] ^ ExpandedKey[6-1][2][3];
  TempKeyCol[3] = TempKeyCol[3] ^ ExpandedKey[6-1][3][3];
  ExpandedKey[6][0][3] = TempKeyCol[0];
  ExpandedKey[6][1][3] = TempKeyCol[1];
  ExpandedKey[6][2][3] = TempKeyCol[2];
  ExpandedKey[6][3][3] = TempKeyCol[3];
  // Outer iteration 7
  TempKeyCol[0] = ExpandedKey[7-1][1][3];
  TempKeyCol[1] = ExpandedKey[7-1][2][3];
  TempKeyCol[2] = ExpandedKey[7-1][3][3];
  TempKeyCol[3] = ExpandedKey[7-1][0][3];
  TempKeyCol[0] = SBox[ TempKeyCol[0] ];
  TempKeyCol[1] = SBox[ TempKeyCol[1] ];
  TempKeyCol[2] = SBox[ TempKeyCol[2] ];
  TempKeyCol[3] = SBox[ TempKeyCol[3] ];
  TempKeyCol[0] ^= RCon[7-1];
  // Iteration 0
  TempKeyCol[0] = TempKeyCol[0] ^ ExpandedKey[7-1][0][0];
  TempKeyCol[1] = TempKeyCol[1] ^ ExpandedKey[7-1][1][0];
  TempKeyCol[2] = TempKeyCol[2] ^ ExpandedKey[7-1][2][0];
  TempKeyCol[3] = TempKeyCol[3] ^ ExpandedKey[7-1][3][0];
  ExpandedKey[7][0][0] = TempKeyCol[0];
  ExpandedKey[7][1][0] = TempKeyCol[1];
  ExpandedKey[7][2][0] = TempKeyCol[2];
  ExpandedKey[7][3][0] = TempKeyCol[3];
  // Iteration 1
  TempKeyCol[0] = TempKeyCol[0] ^ ExpandedKey[7-1][0][1];
  TempKeyCol[1] = TempKeyCol[1] ^ ExpandedKey[7-1][1][1];
  TempKeyCol[2] = TempKeyCol[2] ^ ExpandedKey[7-1][2][1];
  TempKeyCol[3] = TempKeyCol[3] ^ ExpandedKey[7-1][3][1];
  ExpandedKey[7][0][1] = TempKeyCol[0];
  ExpandedKey[7][1][1] = TempKeyCol[1];
  ExpandedKey[7][2][1] = TempKeyCol[2];
  ExpandedKey[7][3][1] = TempKeyCol[3];
  // Iteration 2
  TempKeyCol[0] = TempKeyCol[0] ^ ExpandedKey[7-1][0][2];
  TempKeyCol[1] = TempKeyCol[1] ^ ExpandedKey[7-1][1][2];
  TempKeyCol[2] = TempKeyCol[2] ^ ExpandedKey[7-1][2][2];
  TempKeyCol[3] = TempKeyCol[3] ^ ExpandedKey[7-1][3][2];
  ExpandedKey[7][0][2] = TempKeyCol[0];
  ExpandedKey[7][1][2] = TempKeyCol[1];
  ExpandedKey[7][2][2] = TempKeyCol[2];
  ExpandedKey[7][3][2] = TempKeyCol[3];
  // Iteration 3
  TempKeyCol[0] = TempKeyCol[0] ^ ExpandedKey[7-1][0][3];
  TempKeyCol[1] = TempKeyCol[1] ^ ExpandedKey[7-1][1][3];
  TempKeyCol[2] = TempKeyCol[2] ^ ExpandedKey[7-1][2][3];
  TempKeyCol[3] = TempKeyCol[3] ^ ExpandedKey[7-1][3][3];
  ExpandedKey[7][0][3] = TempKeyCol[0];
  ExpandedKey[7][1][3] = TempKeyCol[1];
  ExpandedKey[7][2][3] = TempKeyCol[2];
  ExpandedKey[7][3][3] = TempKeyCol[3];
  // Outer iteration 8
  TempKeyCol[0] = ExpandedKey[8-1][1][3];
  TempKeyCol[1] = ExpandedKey[8-1][2][3];
  TempKeyCol[2] = ExpandedKey[8-1][3][3];
  TempKeyCol[3] = ExpandedKey[8-1][0][3];
  TempKeyCol[0] = SBox[ TempKeyCol[0] ];
  TempKeyCol[1] = SBox[ TempKeyCol[1] ];
  TempKeyCol[2] = SBox[ TempKeyCol[2] ];
  TempKeyCol[3] = SBox[ TempKeyCol[3] ];
  TempKeyCol[0] ^= RCon[8-1];
  // Iteration 0
  TempKeyCol[0] = TempKeyCol[0] ^ ExpandedKey[8-1][0][0];
  TempKeyCol[1] = TempKeyCol[1] ^ ExpandedKey[8-1][1][0];
  TempKeyCol[2] = TempKeyCol[2] ^ ExpandedKey[8-1][2][0];
  TempKeyCol[3] = TempKeyCol[3] ^ ExpandedKey[8-1][3][0];
  ExpandedKey[8][0][0] = TempKeyCol[0];
  ExpandedKey[8][1][0] = TempKeyCol[1];
  ExpandedKey[8][2][0] = TempKeyCol[2];
  ExpandedKey[8][3][0] = TempKeyCol[3];
  // Iteration 1
  TempKeyCol[0] = TempKeyCol[0] ^ ExpandedKey[8-1][0][1];
  TempKeyCol[1] = TempKeyCol[1] ^ ExpandedKey[8-1][1][1];
  TempKeyCol[2] = TempKeyCol[2] ^ ExpandedKey[8-1][2][1];
  TempKeyCol[3] = TempKeyCol[3] ^ ExpandedKey[8-1][3][1];
  ExpandedKey[8][0][1] = TempKeyCol[0];
  ExpandedKey[8][1][1] = TempKeyCol[1];
  ExpandedKey[8][2][1] = TempKeyCol[2];
  ExpandedKey[8][3][1] = TempKeyCol[3];
  // Iteration 2
  TempKeyCol[0] = TempKeyCol[0] ^ ExpandedKey[8-1][0][2];
  TempKeyCol[1] = TempKeyCol[1] ^ ExpandedKey[8-1][1][2];
  TempKeyCol[2] = TempKeyCol[2] ^ ExpandedKey[8-1][2][2];
  TempKeyCol[3] = TempKeyCol[3] ^ ExpandedKey[8-1][3][2];
  ExpandedKey[8][0][2] = TempKeyCol[0];
  ExpandedKey[8][1][2] = TempKeyCol[1];
  ExpandedKey[8][2][2] = TempKeyCol[2];
  ExpandedKey[8][3][2] = TempKeyCol[3];
  // Iteration 3
  TempKeyCol[0] = TempKeyCol[0] ^ ExpandedKey[8-1][0][3];
  TempKeyCol[1] = TempKeyCol[1] ^ ExpandedKey[8-1][1][3];
  TempKeyCol[2] = TempKeyCol[2] ^ ExpandedKey[8-1][2][3];
  TempKeyCol[3] = TempKeyCol[3] ^ ExpandedKey[8-1][3][3];
  ExpandedKey[8][0][3] = TempKeyCol[0];
  ExpandedKey[8][1][3] = TempKeyCol[1];
  ExpandedKey[8][2][3] = TempKeyCol[2];
  ExpandedKey[8][3][3] = TempKeyCol[3];
  // Outer iteration 9
  TempKeyCol[0] = ExpandedKey[9-1][1][3];
  TempKeyCol[1] = ExpandedKey[9-1][2][3];
  TempKeyCol[2] = ExpandedKey[9-1][3][3];
  TempKeyCol[3] = ExpandedKey[9-1][0][3];
  TempKeyCol[0] = SBox[ TempKeyCol[0] ];
  TempKeyCol[1] = SBox[ TempKeyCol[1] ];
  TempKeyCol[2] = SBox[ TempKeyCol[2] ];
  TempKeyCol[3] = SBox[ TempKeyCol[3] ];
  TempKeyCol[0] ^= RCon[9-1];
  // Iteration 0
  TempKeyCol[0] = TempKeyCol[0] ^ ExpandedKey[9-1][0][0];
  TempKeyCol[1] = TempKeyCol[1] ^ ExpandedKey[9-1][1][0];
  TempKeyCol[2] = TempKeyCol[2] ^ ExpandedKey[9-1][2][0];
  TempKeyCol[3] = TempKeyCol[3] ^ ExpandedKey[9-1][3][0];
  ExpandedKey[9][0][0] = TempKeyCol[0];
  ExpandedKey[9][1][0] = TempKeyCol[1];
  ExpandedKey[9][2][0] = TempKeyCol[2];
  ExpandedKey[9][3][0] = TempKeyCol[3];
  // Iteration 1
  TempKeyCol[0] = TempKeyCol[0] ^ ExpandedKey[9-1][0][1];
  TempKeyCol[1] = TempKeyCol[1] ^ ExpandedKey[9-1][1][1];
  TempKeyCol[2] = TempKeyCol[2] ^ ExpandedKey[9-1][2][1];
  TempKeyCol[3] = TempKeyCol[3] ^ ExpandedKey[9-1][3][1];
  ExpandedKey[9][0][1] = TempKeyCol[0];
  ExpandedKey[9][1][1] = TempKeyCol[1];
  ExpandedKey[9][2][1] = TempKeyCol[2];
  ExpandedKey[9][3][1] = TempKeyCol[3];
  // Iteration 2
  TempKeyCol[0] = TempKeyCol[0] ^ ExpandedKey[9-1][0][2];
  TempKeyCol[1] = TempKeyCol[1] ^ ExpandedKey[9-1][1][2];
  TempKeyCol[2] = TempKeyCol[2] ^ ExpandedKey[9-1][2][2];
  TempKeyCol[3] = TempKeyCol[3] ^ ExpandedKey[9-1][3][2];
  ExpandedKey[9][0][2] = TempKeyCol[0];
  ExpandedKey[9][1][2] = TempKeyCol[1];
  ExpandedKey[9][2][2] = TempKeyCol[2];
  ExpandedKey[9][3][2] = TempKeyCol[3];
  // Iteration 3
  TempKeyCol[0] = TempKeyCol[0] ^ ExpandedKey[9-1][0][3];
  TempKeyCol[1] = TempKeyCol[1] ^ ExpandedKey[9-1][1][3];
  TempKeyCol[2] = TempKeyCol[2] ^ ExpandedKey[9-1][2][3];
  TempKeyCol[3] = TempKeyCol[3] ^ ExpandedKey[9-1][3][3];
  ExpandedKey[9][0][3] = TempKeyCol[0];
  ExpandedKey[9][1][3] = TempKeyCol[1];
  ExpandedKey[9][2][3] = TempKeyCol[2];
  ExpandedKey[9][3][3] = TempKeyCol[3];
  // Outer iteration 10
  TempKeyCol[0] = ExpandedKey[10-1][1][3];
  TempKeyCol[1] = ExpandedKey[10-1][2][3];
  TempKeyCol[2] = ExpandedKey[10-1][3][3];
  TempKeyCol[3] = ExpandedKey[10-1][0][3];
  TempKeyCol[0] = SBox[ TempKeyCol[0] ];
  TempKeyCol[1] = SBox[ TempKeyCol[1] ];
  TempKeyCol[2] = SBox[ TempKeyCol[2] ];
  TempKeyCol[3] = SBox[ TempKeyCol[3] ];
  TempKeyCol[0] ^= RCon[10-1];
  // Iteration 0
  TempKeyCol[0] = TempKeyCol[0] ^ ExpandedKey[10-1][0][0];
  TempKeyCol[1] = TempKeyCol[1] ^ ExpandedKey[10-1][1][0];
  TempKeyCol[2] = TempKeyCol[2] ^ ExpandedKey[10-1][2][0];
  TempKeyCol[3] = TempKeyCol[3] ^ ExpandedKey[10-1][3][0];
  ExpandedKey[10][0][0] = TempKeyCol[0];
  ExpandedKey[10][1][0] = TempKeyCol[1];
  ExpandedKey[10][2][0] = TempKeyCol[2];
  ExpandedKey[10][3][0] = TempKeyCol[3];
  // Iteration 1
  TempKeyCol[0] = TempKeyCol[0] ^ ExpandedKey[10-1][0][1];
  TempKeyCol[1] = TempKeyCol[1] ^ ExpandedKey[10-1][1][1];
  TempKeyCol[2] = TempKeyCol[2] ^ ExpandedKey[10-1][2][1];
  TempKeyCol[3] = TempKeyCol[3] ^ ExpandedKey[10-1][3][1];
  ExpandedKey[10][0][1] = TempKeyCol[0];
  ExpandedKey[10][1][1] = TempKeyCol[1];
  ExpandedKey[10][2][1] = TempKeyCol[2];
  ExpandedKey[10][3][1] = TempKeyCol[3];
  // Iteration 2
  TempKeyCol[0] = TempKeyCol[0] ^ ExpandedKey[10-1][0][2];
  TempKeyCol[1] = TempKeyCol[1] ^ ExpandedKey[10-1][1][2];
  TempKeyCol[2] = TempKeyCol[2] ^ ExpandedKey[10-1][2][2];
  TempKeyCol[3] = TempKeyCol[3] ^ ExpandedKey[10-1][3][2];
  ExpandedKey[10][0][2] = TempKeyCol[0];
  ExpandedKey[10][1][2] = TempKeyCol[1];
  ExpandedKey[10][2][2] = TempKeyCol[2];
  ExpandedKey[10][3][2] = TempKeyCol[3];
  // Iteration 3
  TempKeyCol[0] = TempKeyCol[0] ^ ExpandedKey[10-1][0][3];
  TempKeyCol[1] = TempKeyCol[1] ^ ExpandedKey[10-1][1][3];
  TempKeyCol[2] = TempKeyCol[2] ^ ExpandedKey[10-1][2][3];
  TempKeyCol[3] = TempKeyCol[3] ^ ExpandedKey[10-1][3][3];
  ExpandedKey[10][0][3] = TempKeyCol[0];
  ExpandedKey[10][1][3] = TempKeyCol[1];
  ExpandedKey[10][2][3] = TempKeyCol[2];
  ExpandedKey[10][3][3] = TempKeyCol[3];
}

void AddRoundKey (unsigned char Key[][4], unsigned char StateArray[][4])
{
	StateArray[0][0] ^= Key[0][0];
	StateArray[0][1] ^= Key[0][1];
	StateArray[0][2] ^= Key[0][2];
	StateArray[0][3] ^= Key[0][3];
	StateArray[1][0] ^= Key[1][0];
	StateArray[1][1] ^= Key[1][1];
	StateArray[1][2] ^= Key[1][2];
	StateArray[1][3] ^= Key[1][3];
	StateArray[2][0] ^= Key[2][0];
	StateArray[2][1] ^= Key[2][1];
	StateArray[2][2] ^= Key[2][2];
	StateArray[2][3] ^= Key[2][3];
	StateArray[3][0] ^= Key[3][0];
	StateArray[3][1] ^= Key[3][1];
	StateArray[3][2] ^= Key[3][2];
	StateArray[3][3] ^= Key[3][3];
}

void SubBytes (unsigned char StateArray[][4])
{
  int i, j;
  for (i=0; i<4; i++)
    for (j=0; j<4; j++)
      StateArray[i][j] = SBox[StateArray[i][j]];
}

void SubBytesCalculated (unsigned char StateArray[][4])
{
  unsigned char s, x;
  int i, j, k;
  for (i=0; i<4; i++)
    {    
      for (j=0; j<4; j++)
	{
	  s = x = ee (StateArray[i][j], FX);
	  for (k=0; k<4; k++)
	    {
	      if (s & 0x80)
		s = (s << 1) | 0x01;
	      else
		s = (s << 1) | 0x00;
	      x = s ^ x;
	    }
	  x = x ^ 0x63;
	  StateArray[i][j] = x;
	}
    }
}

void ShiftRows (unsigned char StateArray[][4])
{
  unsigned char x;
  
  x = StateArray[1][0];
  StateArray[1][0] = StateArray[1][1];
  StateArray[1][1] = StateArray[1][2];
  StateArray[1][2] = StateArray[1][3];
  StateArray[1][3] = x;

  x = StateArray[2][0];
  StateArray[2][0] = StateArray[2][2];
  StateArray[2][2] = x;
  x = StateArray[2][1];
  StateArray[2][1] = StateArray[2][3];
  StateArray[2][3] = x;

  x = StateArray[3][3];
  StateArray[3][3] = StateArray[3][2];
  StateArray[3][2] = StateArray[3][1];
  StateArray[3][1] = StateArray[3][0];
  StateArray[3][0] = x;
}

void MixColumns (unsigned char StateArray[][4])
{
  int i;
  unsigned char StateArrayTmp[4][4];

  for (i=0; i<4; i++)
    {
      StateArrayTmp[0][i] = xTime (StateArray[0][i]) ^ xTime (StateArray[1][i]) ^ StateArray[1][i] ^ StateArray[2][i] ^ StateArray[3][i];
      StateArrayTmp[1][i] = StateArray[0][i] ^ xTime (StateArray[1][i]) ^ xTime (StateArray[2][i]) ^ StateArray[2][i] ^ StateArray[3][i];
      StateArrayTmp[2][i] = StateArray[0][i] ^ StateArray[1][i] ^ xTime (StateArray[2][i]) ^ xTime (StateArray[3][i]) ^ StateArray[3][i];
      StateArrayTmp[3][i] = xTime (StateArray[0][i]) ^ StateArray[0][i] ^ StateArray[1][i] ^ StateArray[2][i] ^ xTime (StateArray[3][i]);
    }

  memcpy (StateArray, StateArrayTmp, 4 * 4 * sizeof (unsigned char));
}

void InvSubBytes (unsigned char StateArray[][4])
{
  int i, j;
  for (i=0; i<4; i++)
    for (j=0; j<4; j++)
      StateArray[i][j] = invSBox[StateArray[i][j]];
}

void InvSubBytesCalculated (unsigned char StateArray[][4])
{
  unsigned char s, x;
  int i, j, k;
  unsigned char c = 0x63;
  for (i=0; i<4; i++)
    {    
      for (j=0; j<4; j++)
	{
	  s = x = StateArray[i][j];
	  s = (s << 1) | (s >> 7); // rotate left 1 to start (msb: 6)
	  x = (x << 1) | (x >> 7); // rotate left 1 to start (msb: 6)
	  s = (s << 1) | (s >> 7); // rotate left 1 (msb: 5)
	  s = (s << 1) | (s >> 7); // rotate left 1 (msb: 4)
	  x ^= s;
	  s = (s << 1) | (s >> 7); // rotate left 1 (msb: 3)
	  s = (s << 1) | (s >> 7); // rotate left 1 (msb: 2)
	  s = (s << 1) | (s >> 7); // rotate left 1 (msb: 1)
	  x ^= s;
	  x ^= 0x05;
	  StateArray[i][j] = ee (x, FX);
	}
    }
}

void InvShiftRows (unsigned char StateArray[][4])
{
  // rotate right ->!
  unsigned char x;
  
  x = StateArray[1][3];
  StateArray[1][3] = StateArray[1][2];
  StateArray[1][2] = StateArray[1][1];
  StateArray[1][1] = StateArray[1][0];
  StateArray[1][0] = x;
  
  x = StateArray[2][0];
  StateArray[2][0] = StateArray[2][2];
  StateArray[2][2] = x;
  x = StateArray[2][1];
  StateArray[2][1] = StateArray[2][3];
  StateArray[2][3] = x;
  
  x = StateArray[3][0];
  StateArray[3][0] = StateArray[3][1];
  StateArray[3][1] = StateArray[3][2];
  StateArray[3][2] = StateArray[3][3];
  StateArray[3][3] = x;
  
  // row #1 - rotate 1 left
  // TODO our code here

  // row #2 - rotate 2 left
  // TODO our code here

  // row #3 - rotate 3 left
  // TODO our code here
}

void InvMixColumns (unsigned char StateArray[][4])
{
  int i;
  unsigned char StateArrayTmp[4][4];

  for (i=0; i<4; i++)
    {
	  StateArrayTmp[0][i] = multiply(0x0e,StateArray[0][i])^multiply(0x0b,StateArray[1][i])^multiply(0x0d,StateArray[2][i])^multiply(0x09,StateArray[3][i]);
      StateArrayTmp[1][i] = multiply(0x09,StateArray[0][i])^multiply(0x0e,StateArray[1][i])^multiply(0x0b,StateArray[2][i])^multiply(0x0d,StateArray[3][i]);
      StateArrayTmp[2][i] = multiply(0x0d,StateArray[0][i])^multiply(0x09,StateArray[1][i])^multiply(0x0e,StateArray[2][i])^multiply(0x0b,StateArray[3][i]);
      StateArrayTmp[3][i] = multiply(0x0b,StateArray[0][i])^multiply(0x0d,StateArray[1][i])^multiply(0x09,StateArray[2][i])^multiply(0x0e,StateArray[3][i]);
    }

  memcpy (StateArray, StateArrayTmp, 4 * 4 * sizeof (unsigned char));
}

void AES_printf (unsigned char AES_StateArray[][4])
{
  int i;
  printf ("   W0  W1  W2  W3\r\n\n");
  for (i=0; i<4; i++)
    {
      printf("   %02x  %02x  %02x  %02x\r\n",
		 AES_StateArray[i][0],
		 AES_StateArray[i][1],
		 AES_StateArray[i][2],
		 AES_StateArray[i][3]);
      printf("\n");
    }
}
