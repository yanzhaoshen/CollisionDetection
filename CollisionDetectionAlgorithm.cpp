/**********************************************************************************/
//Improved MD5 Collision Detection algorithm									  
//================================================================================
//Source code files:															  													
//		CollisionDetectionAlgorithm.h	
//		CollisionDetectionAlgorithm.cpp
//		Main.cpp
//Win32 executable:
//		ImprovedMD5CollisionDetectionAlgorithm.exe
//=================================================================================
//Copyright
//Yanzhao Shen, 2020. All rights reserved.
//=================================================================================
//Disclaimer
//This software is provided as is. Use is at the user's risk.
//No guarantee whatsoever is given on how it may function or malfunction. 
//Support cannot be expected.
//This software is meant for scientific and educational purposes only.
//It is forbidden to use it for other than scientific or educational purposes.
//In particular, commercial and malicious use is not allowed.
//Further distribution of this software, by whatever means, 
//is not allowed without our consent.
//This includes publication of source code or executables in printed form, 
//on websites, newsgroups, CD-ROM's, etc.
//Changing the (source) code without our consent is not allowed.
//In all versions of the source code this disclaimer, 
//the copyright notice and the version number should be present.
/**********************************************************************************/

#include "CollisionDetectionAlgorithm.h"
#include <iostream>
using namespace std;

/* Distinguishable Set,				  00      01      10      11    mask */
int32 distinguishableSet[][5] = {{0x0000, 0x1555, 0x2AAA, 0x3FFF, 0x3FFF},	/* DS1 */
								 {0x2AA0, 0x3FF5, 0x000A, 0x15FF, 0x3FFF},	/* DS2 */
								 {0x1400, 0x0155, 0x3EAA, 0x2BFF, 0x3FFF},	/* DS3 */
								 {0x2800, 0x3D55, 0x02AA, 0x17FF, 0x3FFF},	/* DS4 */
								 {0x3EA0, 0x2BF5, 0x140A, 0x015F, 0x3FFF},	/* DS5 */
								 {0x1550, 0x0005, 0x3FFA, 0x2AAF, 0x3FFF},	/* DS6 */
								 {0x2A00, 0x3F55, 0x00AA, 0x15FF, 0x3FFF},	/* DS7 */
								 {0x0554, 0x1001, 0x2FFE, 0x3AAB, 0x3FFF},	/* DS8 */
								 {0x1000, 0x1555, 0x1AAA, 0x1FFF, 0x3FFF},	/* DS9 */
								 {0x1800, 0x1D55, 0x12AA, 0x17FF, 0x3FFF},	/* DS10 */
								 {0x1554, 0x1555,     -1,     -1, 0x3FFF},	/* DS11, NoN = -1 */
								 {0x0300, 0x0255, 0x03AA, 0x02FF, 0x07FF},	/* DS12 */
								 {0x0180, 0x01D5, 0x012A, 0x017F, 0x03FF},	/* DS13 */
								 {0x0000, 0x0055, 0x00AA, 0x00FF, 0x03FF}};	/* DS14 */

int32 individualCheckedSet[][5] = {{0x0600, 0x0755, 0x04AA, 0x05FF, 0x0FFF},	/* ICS3, 0 */
								   {0x0300, 0x0255, 0x03AA, 0x02FF, 0x07FF},	/* ICS7, 1 */
								   {0x0180, 0x01D5, 0x012A, 0x017F, 0x03FF},	/* ICS8, 2 */
								   {0x0080, 0x1580, 0x2A80, 0x3F80, 0x3FC0},	/* ICS1, 3 */
								   {0x00C0, 0x0095, 0x00EA, 0x00BF, 0x01FF},	/* ICS2, 4 */
								   {0x0300, 0x0255, 0x03AA, 0x02FF, 0x07FF},	/* ICS5, 5 */
								   {0x0100, 0x1500, 0x2B00, 0x3F00, 0x3F80},	/* ICS4, 6 */
								   {0x0060, 0x0075, 0x004A, 0x005F, 0x00FF},	/* ICS4, 7 */
								   {0x0080, 0x1580, 0x2A80, 0x3F80, 0x3FC0},	/* ICS6, 8 */
								   {0x0030, 0x0025, 0x003A, 0x002F, 0x007F}};	/* ICS6, 9 */

//compression function of MD5, only used to check other algorithms
void Compression(uint32 ihv[], const uint32 block[]){
	uint32 a = ihv[0];
	uint32 b = ihv[1];
	uint32 c = ihv[2];
	uint32 d = ihv[3];
	/* Round 1 */
	STEPFUNCTION(F, a, b, c, d,  7, 0xd76aa478, block[ 0]);	/*  0 */
	STEPFUNCTION(F, d, a, b, c, 12, 0xe8c7b756, block[ 1]);	/*  1 */
	STEPFUNCTION(F, c, d, a, b, 17, 0x242070db, block[ 2]);	/*  2 */
	STEPFUNCTION(F, b, c, d, a, 22, 0xc1bdceee, block[ 3]);	/*  3 */
	STEPFUNCTION(F, a, b, c, d,  7, 0xf57c0faf, block[ 4]);	/*  4 */
	STEPFUNCTION(F, d, a, b, c, 12, 0x4787c62a, block[ 5]);	/*  5 */
	STEPFUNCTION(F, c, d, a, b, 17, 0xa8304613, block[ 6]);	/*  6 */
	STEPFUNCTION(F, b, c, d, a, 22, 0xfd469501, block[ 7]);	/*  7 */
	STEPFUNCTION(F, a, b, c, d,  7, 0x698098d8, block[ 8]);	/*  8 */
	STEPFUNCTION(F, d, a, b, c, 12, 0x8b44f7af, block[ 9]);	/*  9 */
	STEPFUNCTION(F, c, d, a, b, 17, 0xffff5bb1, block[10]);	/* 10 */
	STEPFUNCTION(F, b, c, d, a, 22, 0x895cd7be, block[11]);	/* 11 */
	STEPFUNCTION(F, a, b, c, d,  7, 0x6b901122, block[12]);	/* 12 */
	STEPFUNCTION(F, d, a, b, c, 12, 0xfd987193, block[13]);	/* 13 */
	STEPFUNCTION(F, c, d, a, b, 17, 0xa679438e, block[14]);	/* 14 */
	STEPFUNCTION(F, b, c, d, a, 22, 0x49b40821, block[15]);	/* 15 */
	/* Round 2 */
	STEPFUNCTION(G, a, b, c, d,  5, 0xf61e2562, block[ 1]);	/* 16 */
	STEPFUNCTION(G, d, a, b, c,  9, 0xc040b340, block[ 6]);	/* 17 */
	STEPFUNCTION(G, c, d, a, b, 14, 0x265e5a51, block[11]);	/* 18 */
	STEPFUNCTION(G, b, c, d, a, 20, 0xe9b6c7aa, block[ 0]);	/* 19 */
	STEPFUNCTION(G, a, b, c, d,  5, 0xd62f105d, block[ 5]);	/* 20 */
	STEPFUNCTION(G, d, a, b, c,  9, 0x02441453, block[10]);	/* 21 */
	STEPFUNCTION(G, c, d, a, b, 14, 0xd8a1e681, block[15]);	/* 22 */
	STEPFUNCTION(G, b, c, d, a, 20, 0xe7d3fbc8, block[ 4]);	/* 23 */
	STEPFUNCTION(G, a, b, c, d,  5, 0x21e1cde6, block[ 9]);	/* 24 */
	STEPFUNCTION(G, d, a, b, c,  9, 0xc33707d6, block[14]);	/* 25 */
	STEPFUNCTION(G, c, d, a, b, 14, 0xf4d50d87, block[ 3]);	/* 26 */
	STEPFUNCTION(G, b, c, d, a, 20, 0x455a14ed, block[ 8]);	/* 27 */
	STEPFUNCTION(G, a, b, c, d,  5, 0xa9e3e905, block[13]);	/* 28 */
	STEPFUNCTION(G, d, a, b, c,  9, 0xfcefa3f8, block[ 2]);	/* 29 */
	STEPFUNCTION(G, c, d, a, b, 14, 0x676f02d9, block[ 7]);	/* 30 */
	STEPFUNCTION(G, b, c, d, a, 20, 0x8d2a4c8a, block[12]);	/* 31 */
	/* Round 3 */
	STEPFUNCTION(H, a, b, c, d,  4, 0xfffa3942, block[ 5]);	/* 32 */
	STEPFUNCTION(H, d, a, b, c, 11, 0x8771f681, block[ 8]);	/* 33 */
	STEPFUNCTION(H, c, d, a, b, 16, 0x6d9d6122, block[11]);	/* 34 */
	STEPFUNCTION(H, b, c, d, a, 23, 0xfde5380c, block[14]);	/* 35 */
	STEPFUNCTION(H, a, b, c, d,  4, 0xa4beea44, block[ 1]);	/* 36 */
	STEPFUNCTION(H, d, a, b, c, 11, 0x4bdecfa9, block[ 4]);	/* 37 */
	STEPFUNCTION(H, c, d, a, b, 16, 0xf6bb4b60, block[ 7]);	/* 38 */
	STEPFUNCTION(H, b, c, d, a, 23, 0xbebfbc70, block[10]);	/* 39 */
	STEPFUNCTION(H, a, b, c, d,  4, 0x289b7ec6, block[13]);	/* 40 */
	STEPFUNCTION(H, d, a, b, c, 11, 0xeaa127fa, block[ 0]);	/* 41 */
	STEPFUNCTION(H, c, d, a, b, 16, 0xd4ef3085, block[ 3]);	/* 42 */
	STEPFUNCTION(H, b, c, d, a, 23, 0x04881d05, block[ 6]);	/* 43 */
	STEPFUNCTION(H, a, b, c, d,  4, 0xd9d4d039, block[ 9]);	/* 44 */
	STEPFUNCTION(H, d, a, b, c, 11, 0xe6db99e5, block[12]);	/* 45 */
	STEPFUNCTION(H, c, d, a, b, 16, 0x1fa27cf8, block[15]);	/* 46 */
	STEPFUNCTION(H, b, c, d, a, 23, 0xc4ac5665, block[ 2]);	/* 47 */
	/* Round 4 */
	STEPFUNCTION(I, a, b, c, d,  6, 0xf4292244, block[ 0]);	/* 48 */
	STEPFUNCTION(I, d, a, b, c, 10, 0x432aff97, block[ 7]);	/* 49 */
	STEPFUNCTION(I, c, d, a, b, 15, 0xab9423a7, block[14]);	/* 50 */
	STEPFUNCTION(I, b, c, d, a, 21, 0xfc93a039, block[ 5]);	/* 51 */
	STEPFUNCTION(I, a, b, c, d,  6, 0x655b59c3, block[12]);	/* 52 */
	STEPFUNCTION(I, d, a, b, c, 10, 0x8f0ccc92, block[ 3]);	/* 53 */
	STEPFUNCTION(I, c, d, a, b, 15, 0xffeff47d, block[10]);	/* 54 */
	STEPFUNCTION(I, b, c, d, a, 21, 0x85845dd1, block[ 1]);	/* 55 */
	STEPFUNCTION(I, a, b, c, d,  6, 0x6fa87e4f, block[ 8]);	/* 56 */
	STEPFUNCTION(I, d, a, b, c, 10, 0xfe2ce6e0, block[15]);	/* 57 */
	STEPFUNCTION(I, c, d, a, b, 15, 0xa3014314, block[ 6]);	/* 58 */
	STEPFUNCTION(I, b, c, d, a, 21, 0x4e0811a1, block[13]);	/* 59 */
	STEPFUNCTION(I, a, b, c, d,  6, 0xf7537e82, block[ 4]);	/* 60 */
	STEPFUNCTION(I, d, a, b, c, 10, 0xbd3af235, block[11]);	/* 61 */
	STEPFUNCTION(I, c, d, a, b, 15, 0x2ad7d2bb, block[ 2]);	/* 62 */
	STEPFUNCTION(I, b, c, d, a, 21, 0xeb86d391, block[ 9]);	/* 63 */
	/* Output */
	ihv[0] += a;	/* ihv[0] + cv[60] */
	ihv[1] += b;	/* ihv[1] + cv[63] */
	ihv[2] += c;	/* ihv[2] + cv[62] */
	ihv[3] += d;	/* ihv[3] + cv[61] */
}
//modified compression function of MD5, 
//input = ihv_k and block_k, 
//output = ihv_{k+1}, (cv37, cv38, cv39, cv40), sufficient condition vector(contain 5 values).
void Compression_Modify(uint32 ihv[], uint32 cv[], uint32 scv[], const uint32 block[]){
	uint32 a = ihv[0];
	uint32 b = ihv[1];
	uint32 c = ihv[2];
	uint32 d = ihv[3];
	/* Rround 1 */
	STEPFUNCTION(F, a, b, c, d,  7, 0xd76aa478, block[ 0]);	/*  0 */
	STEPFUNCTION(F, d, a, b, c, 12, 0xe8c7b756, block[ 1]);	/*  1 */
	STEPFUNCTION(F, c, d, a, b, 17, 0x242070db, block[ 2]);	/*  2 */
	STEPFUNCTION(F, b, c, d, a, 22, 0xc1bdceee, block[ 3]);	/*  3 */
	STEPFUNCTION(F, a, b, c, d,  7, 0xf57c0faf, block[ 4]);	/*  4 */
	STEPFUNCTION(F, d, a, b, c, 12, 0x4787c62a, block[ 5]);	/*  5 */
	STEPFUNCTION(F, c, d, a, b, 17, 0xa8304613, block[ 6]);	/*  6 */
	STEPFUNCTION(F, b, c, d, a, 22, 0xfd469501, block[ 7]);	/*  7 */
	STEPFUNCTION(F, a, b, c, d,  7, 0x698098d8, block[ 8]);	/*  8 */
	STEPFUNCTION(F, d, a, b, c, 12, 0x8b44f7af, block[ 9]);	/*  9 */
	STEPFUNCTION(F, c, d, a, b, 17, 0xffff5bb1, block[10]);	/* 10 */
	STEPFUNCTION(F, b, c, d, a, 22, 0x895cd7be, block[11]);	/* 11 */
	STEPFUNCTION(F, a, b, c, d,  7, 0x6b901122, block[12]);	/* 12 */
	STEPFUNCTION(F, d, a, b, c, 12, 0xfd987193, block[13]);	/* 13 */
	STEPFUNCTION(F, c, d, a, b, 17, 0xa679438e, block[14]);	/* 14 */
	STEPFUNCTION(F, b, c, d, a, 22, 0x49b40821, block[15]);	/* 15 */
	/* round 2 */
	STEPFUNCTION(G, a, b, c, d,  5, 0xf61e2562, block[ 1]);	/* 16 */
	STEPFUNCTION(G, d, a, b, c,  9, 0xc040b340, block[ 6]);	/* 17 */
	STEPFUNCTION(G, c, d, a, b, 14, 0x265e5a51, block[11]);	/* 18 */
	STEPFUNCTION(G, b, c, d, a, 20, 0xe9b6c7aa, block[ 0]);	/* 19 */
	STEPFUNCTION(G, a, b, c, d,  5, 0xd62f105d, block[ 5]);	/* 20 */
	STEPFUNCTION(G, d, a, b, c,  9, 0x02441453, block[10]);	/* 21 */
	STEPFUNCTION(G, c, d, a, b, 14, 0xd8a1e681, block[15]);	/* 22 */
	STEPFUNCTION(G, b, c, d, a, 20, 0xe7d3fbc8, block[ 4]);	/* 23 */
	STEPFUNCTION(G, a, b, c, d,  5, 0x21e1cde6, block[ 9]);	/* 24 */
	STEPFUNCTION(G, d, a, b, c,  9, 0xc33707d6, block[14]);	/* 25 */
	STEPFUNCTION(G, c, d, a, b, 14, 0xf4d50d87, block[ 3]);	/* 26 */
	STEPFUNCTION(G, b, c, d, a, 20, 0x455a14ed, block[ 8]);	/* 27 */
	STEPFUNCTION(G, a, b, c, d,  5, 0xa9e3e905, block[13]);	/* 28 */
	STEPFUNCTION(G, d, a, b, c,  9, 0xfcefa3f8, block[ 2]);	/* 29 */
	STEPFUNCTION(G, c, d, a, b, 14, 0x676f02d9, block[ 7]);	/* 30 */
	STEPFUNCTION(G, b, c, d, a, 20, 0x8d2a4c8a, block[12]);	/* 31 */
	/* round 3 */
	STEPFUNCTION(H, a, b, c, d,  4, 0xfffa3942, block[ 5]);	/* 32 */
	STEPFUNCTION(H, d, a, b, c, 11, 0x8771f681, block[ 8]);	/* 33 */
	STEPFUNCTION(H, c, d, a, b, 16, 0x6d9d6122, block[11]);	/* 34 */
	STEPFUNCTION(H, b, c, d, a, 23, 0xfde5380c, block[14]);	/* 35 */
	STEPFUNCTION(H, a, b, c, d,  4, 0xa4beea44, block[ 1]);	/* 36 */
	STEPFUNCTION(H, d, a, b, c, 11, 0x4bdecfa9, block[ 4]);	/* 37 */
	STEPFUNCTION(H, c, d, a, b, 16, 0xf6bb4b60, block[ 7]);	/* 38 */
	STEPFUNCTION(H, b, c, d, a, 23, 0xbebfbc70, block[10]);	/* 39 */
	STEPFUNCTION(H, a, b, c, d,  4, 0x289b7ec6, block[13]);	/* 40 */
	cv[0] = d; cv[1] = c; cv[2] = b; cv[3] = a;	//output cv37, cv38, cv39 and cv40
	STEPFUNCTION(H, d, a, b, c, 11, 0xeaa127fa, block[ 0]);	/* 41 */
	STEPFUNCTION(H, c, d, a, b, 16, 0xd4ef3085, block[ 3]);	/* 42 */
	STEPFUNCTION(H, b, c, d, a, 23, 0x04881d05, block[ 6]);	/* 43 */
	STEPFUNCTION(H, a, b, c, d,  4, 0xd9d4d039, block[ 9]);	/* 44 */
	STEPFUNCTION(H, d, a, b, c, 11, 0xe6db99e5, block[12]);	/* 45 */
	//output cv45[31], cv45[5], cv45[9], cv45[14] and cv45[20]
	GetBits(scv[0], scv[1], scv[2], scv[3], scv[4], d);
	STEPFUNCTION(H, c, d, a, b, 16, 0x1fa27cf8, block[15]);	/* 46 */
	//output cv46[31], cv46[5], cv46[9], cv46[14] and cv46[20]
	GetBits(scv[0], scv[1], scv[2], scv[3], scv[4], c);
	STEPFUNCTION(H, b, c, d, a, 23, 0xc4ac5665, block[ 2]);	/* 47 */
	//output cv47[31], cv47[5], cv47[9], cv47[14] and cv47[20]
	GetBits(scv[0], scv[1], scv[2], scv[3], scv[4], b);
	/* round 4 */
	STEPFUNCTION(I, a, b, c, d,  6, 0xf4292244, block[ 0]);	/* 48 */
	//output cv48[31], cv48[5], cv48[9], cv48[14] and cv48[20]
	GetBits(scv[0], scv[1], scv[2], scv[3], scv[4], a);
	STEPFUNCTION(I, d, a, b, c, 10, 0x432aff97, block[ 7]);	/* 49 */
	//output cv49[31], cv49[5], cv49[9], cv49[14] and cv49[20]
	GetBits(scv[0], scv[1], scv[2], scv[3], scv[4], d);
	STEPFUNCTION(I, c, d, a, b, 15, 0xab9423a7, block[14]);	/* 50 */
	//output cv50[31], cv50[5], cv50[9], cv50[14] and cv50[20]
	GetBits(scv[0], scv[1], scv[2], scv[3], scv[4], c);
	STEPFUNCTION(I, b, c, d, a, 21, 0xfc93a039, block[ 5]);	/* 51 */
	//output cv51[31], cv51[5], cv51[9], cv51[14] and cv51[20]
	GetBits(scv[0], scv[1], scv[2], scv[3], scv[4], b);
	STEPFUNCTION(I, a, b, c, d,  6, 0x655b59c3, block[12]);	/* 52 */
	//output cv52[31], cv52[5], cv52[9], cv52[14] and cv52[20]
	GetBits(scv[0], scv[1], scv[2], scv[3], scv[4], a);
	STEPFUNCTION(I, d, a, b, c, 10, 0x8f0ccc92, block[ 3]);	/* 53 */
	//output cv53[31], cv53[5], cv53[9], cv53[14] and cv53[20]
	GetBits(scv[0], scv[1], scv[2], scv[3], scv[4], d);
	STEPFUNCTION(I, c, d, a, b, 15, 0xffeff47d, block[10]);	/* 54 */
	//output cv54[31], cv54[5], cv54[9], cv54[14] and cv54[20]
	GetBits(scv[0], scv[1], scv[2], scv[3], scv[4], c);
	STEPFUNCTION(I, b, c, d, a, 21, 0x85845dd1, block[ 1]);	/* 55 */
	//output cv55[31], cv55[5], cv55[9], cv55[14] and cv55[20]
	GetBits(scv[0], scv[1], scv[2], scv[3], scv[4], b);
	STEPFUNCTION(I, a, b, c, d,  6, 0x6fa87e4f, block[ 8]);	/* 56 */
	//output cv56[31], cv56[5], cv56[9], cv56[14] and cv56[20]
	GetBits(scv[0], scv[1], scv[2], scv[3], scv[4], a);
	STEPFUNCTION(I, d, a, b, c, 10, 0xfe2ce6e0, block[15]);	/* 57 */
	//output cv57[31], cv57[5], cv57[9], cv57[14] and cv57[20]
	GetBits(scv[0], scv[1], scv[2], scv[3], scv[4], d);
	STEPFUNCTION(I, c, d, a, b, 15, 0xa3014314, block[ 6]);	/* 58 */
	//output cv58[31], cv58[5], cv58[9], cv58[14] and cv58[20]
	GetBits(scv[0], scv[1], scv[2], scv[3], scv[4], c);
	STEPFUNCTION(I, b, c, d, a, 21, 0x4e0811a1, block[13]);	/* 59 */
	STEPFUNCTION(I, a, b, c, d,  6, 0xf7537e82, block[ 4]);	/* 60 */
	STEPFUNCTION(I, d, a, b, c, 10, 0xbd3af235, block[11]);	/* 61 */
	STEPFUNCTION(I, c, d, a, b, 15, 0x2ad7d2bb, block[ 2]);	/* 62 */
	STEPFUNCTION(I, b, c, d, a, 21, 0xeb86d391, block[ 9]);	/* 63 */
	/* output */
	ihv[0] += a;	/* ihv[0] + cv[60] */
	ihv[1] += b;	/* ihv[1] + cv[63] */
	ihv[2] += c;	/* ihv[2] + cv[62] */
	ihv[3] += d;	/* ihv[3] + cv[61] */
}
//reverse compression function,
//input are cv37, cv38, cv39, cv40 and message block,
//backward is to obtain ihv_k of the message block,
//forward is to get ihv_{k+1} of the message block.
void ReverseCompression(uint32 ihv[], const uint32 cv[], const uint32 block[]){
	uint32 a, b, c, d, aa, bb, cc, dd, tblock[16];
	d = dd = cv[0];	//copy chaining values cv37, cv38, cv39 and cv40
	c = cc = cv[1];
	b = bb = cv[2];
	a = aa = cv[3];
	memcpy(tblock, block, 64);	//copy block to temporary variables
	//backward
	REVSTEPFUNCTION(H, a, b, c, d,  4, 0x289b7ec6, tblock[13]);	/* 40 */
	REVSTEPFUNCTION(H, b, c, d, a, 23, 0xbebfbc70, tblock[10]);	/* 39 */
	REVSTEPFUNCTION(H, c, d, a, b, 16, 0xf6bb4b60, tblock[ 7]);	/* 38 */
	REVSTEPFUNCTION(H, d, a, b, c, 11, 0x4bdecfa9, tblock[ 4]);	/* 37 */
	REVSTEPFUNCTION(H, a, b, c, d,  4, 0xa4beea44, tblock[ 1]);	/* 36 */
	REVSTEPFUNCTION(H, b, c, d, a, 23, 0xfde5380c, tblock[14]);	/* 35 */
	REVSTEPFUNCTION(H, c, d, a, b, 16, 0x6d9d6122, tblock[11]);	/* 34 */
	REVSTEPFUNCTION(H, d, a, b, c, 11, 0x8771f681, tblock[ 8]);	/* 33 */
	REVSTEPFUNCTION(H, a, b, c, d,  4, 0xfffa3942, tblock[ 5]);	/* 32 */
	/* Round 2 */
	REVSTEPFUNCTION(G, b, c, d, a, 20, 0x8d2a4c8a, tblock[12]);	/* 31 */
	REVSTEPFUNCTION(G, c, d, a, b, 14, 0x676f02d9, tblock[ 7]);	/* 30 */
	REVSTEPFUNCTION(G, d, a, b, c,  9, 0xfcefa3f8, tblock[ 2]);	/* 29 */
	REVSTEPFUNCTION(G, a, b, c, d,  5, 0xa9e3e905, tblock[13]);	/* 28 */
	REVSTEPFUNCTION(G, b, c, d, a, 20, 0x455a14ed, tblock[ 8]);	/* 27 */
	REVSTEPFUNCTION(G, c, d, a, b, 14, 0xf4d50d87, tblock[ 3]);	/* 26 */
	REVSTEPFUNCTION(G, d, a, b, c,  9, 0xc33707d6, tblock[14]);	/* 25 */
	REVSTEPFUNCTION(G, a, b, c, d,  5, 0x21e1cde6, tblock[ 9]);	/* 24 */
	REVSTEPFUNCTION(G, b, c, d, a, 20, 0xe7d3fbc8, tblock[ 4]);	/* 23 */
	REVSTEPFUNCTION(G, c, d, a, b, 14, 0xd8a1e681, tblock[15]);	/* 22 */
	REVSTEPFUNCTION(G, d, a, b, c,  9, 0x02441453, tblock[10]);	/* 21 */
	REVSTEPFUNCTION(G, a, b, c, d,  5, 0xd62f105d, tblock[ 5]);	/* 20 */
	REVSTEPFUNCTION(G, b, c, d, a, 20, 0xe9b6c7aa, tblock[ 0]);	/* 19 */
	REVSTEPFUNCTION(G, c, d, a, b, 14, 0x265e5a51, tblock[11]);	/* 18 */
	REVSTEPFUNCTION(G, d, a, b, c,  9, 0xc040b340, tblock[ 6]);	/* 17 */
	REVSTEPFUNCTION(G, a, b, c, d,  5, 0xf61e2562, tblock[ 1]);	/* 16 */
	/* Round 1 */
	REVSTEPFUNCTION(F, b, c, d, a, 22, 0x49b40821, tblock[15]);	/* 15 */
	REVSTEPFUNCTION(F, c, d, a, b, 17, 0xa679438e, tblock[14]);	/* 14 */
	REVSTEPFUNCTION(F, d, a, b, c, 12, 0xfd987193, tblock[13]);	/* 13 */
	REVSTEPFUNCTION(F, a, b, c, d,  7, 0x6b901122, tblock[12]);	/* 12 */
	REVSTEPFUNCTION(F, b, c, d, a, 22, 0x895cd7be, tblock[11]);	/* 11 */
	REVSTEPFUNCTION(F, c, d, a, b, 17, 0xffff5bb1, tblock[10]);	/* 10 */
	REVSTEPFUNCTION(F, d, a, b, c, 12, 0x8b44f7af, tblock[ 9]);	/*  9 */
	REVSTEPFUNCTION(F, a, b, c, d,  7, 0x698098d8, tblock[ 8]);	/*  8 */
	REVSTEPFUNCTION(F, b, c, d, a, 22, 0xfd469501, tblock[ 7]);	/*  7 */
	REVSTEPFUNCTION(F, c, d, a, b, 17, 0xa8304613, tblock[ 6]);	/*  6 */
	REVSTEPFUNCTION(F, d, a, b, c, 12, 0x4787c62a, tblock[ 5]);	/*  5 */
	REVSTEPFUNCTION(F, a, b, c, d,  7, 0xf57c0faf, tblock[ 4]);	/*  4 */
	REVSTEPFUNCTION(F, b, c, d, a, 22, 0xc1bdceee, tblock[ 3]);	/*  3 */
	REVSTEPFUNCTION(F, c, d, a, b, 17, 0x242070db, tblock[ 2]);	/*  2 */
	REVSTEPFUNCTION(F, d, a, b, c, 12, 0xe8c7b756, tblock[ 1]);	/*  1 */
	REVSTEPFUNCTION(F, a, b, c, d,  7, 0xd76aa478, tblock[ 0]);	/*  0 */
	//forward
	STEPFUNCTION(H, dd, aa, bb, cc, 11, 0xeaa127fa, tblock[ 0]);	/* 41 */
	STEPFUNCTION(H, cc, dd, aa, bb, 16, 0xd4ef3085, tblock[ 3]);	/* 42 */
	STEPFUNCTION(H, bb, cc, dd, aa, 23, 0x04881d05, tblock[ 6]);	/* 43 */
	STEPFUNCTION(H, aa, bb, cc, dd,  4, 0xd9d4d039, tblock[ 9]);	/* 44 */
	STEPFUNCTION(H, dd, aa, bb, cc, 11, 0xe6db99e5, tblock[12]);	/* 45 */
	STEPFUNCTION(H, cc, dd, aa, bb, 16, 0x1fa27cf8, tblock[15]);	/* 46 */
	STEPFUNCTION(H, bb, cc, dd, aa, 23, 0xc4ac5665, tblock[ 2]);	/* 47 */
	/* Round 4 */
	STEPFUNCTION(I, aa, bb, cc, dd,  6, 0xf4292244, tblock[ 0]);	/* 48 */
	STEPFUNCTION(I, dd, aa, bb, cc, 10, 0x432aff97, tblock[ 7]);	/* 49 */
	STEPFUNCTION(I, cc, dd, aa, bb, 15, 0xab9423a7, tblock[14]);	/* 50 */
	STEPFUNCTION(I, bb, cc, dd, aa, 21, 0xfc93a039, tblock[ 5]);	/* 51 */
	STEPFUNCTION(I, aa, bb, cc, dd,  6, 0x655b59c3, tblock[12]);	/* 52 */
	STEPFUNCTION(I, dd, aa, bb, cc, 10, 0x8f0ccc92, tblock[ 3]);	/* 53 */
	STEPFUNCTION(I, cc, dd, aa, bb, 15, 0xffeff47d, tblock[10]);	/* 54 */
	STEPFUNCTION(I, bb, cc, dd, aa, 21, 0x85845dd1, tblock[ 1]);	/* 55 */
	STEPFUNCTION(I, aa, bb, cc, dd,  6, 0x6fa87e4f, tblock[ 8]);	/* 56 */
	STEPFUNCTION(I, dd, aa, bb, cc, 10, 0xfe2ce6e0, tblock[15]);	/* 57 */
	STEPFUNCTION(I, cc, dd, aa, bb, 15, 0xa3014314, tblock[ 6]);	/* 58 */
	STEPFUNCTION(I, bb, cc, dd, aa, 21, 0x4e0811a1, tblock[13]);	/* 59 */
	STEPFUNCTION(I, aa, bb, cc, dd,  6, 0xf7537e82, tblock[ 4]);	/* 60 */
	STEPFUNCTION(I, dd, aa, bb, cc, 10, 0xbd3af235, tblock[11]);	/* 61 */
	STEPFUNCTION(I, cc, dd, aa, bb, 15, 0x2ad7d2bb, tblock[ 2]);	/* 62 */
	STEPFUNCTION(I, bb, cc, dd, aa, 21, 0xeb86d391, tblock[ 9]);	/* 63 */
	//output ihv_{k+1} of the new message block
	ihv[0] = a + aa;
	ihv[1] = b + bb;
	ihv[2] = c + cc;
	ihv[3] = d + dd;
}
//Determine whether two hash values are equal
inline bool Equal(const uint32 cv1[], const uint32 cv2[]){
	if( (cv1[0] == cv2[0]) && (cv1[1] == cv2[1]) && (cv1[2] == cv2[2]) && (cv1[3] == cv2[3]) ){
		return true;
	}
	return false;
}
//distinguishable set check function,
//each element has different message differences, main function is a program entry,
//details implementation is coded in DSFunction_1 to DSFunction_15
//implementation of DS1 Element, cover 69 cases
bool DSFunction_1(const uint32 cv[], const uint32 ihv[], const uint32 block[]){
	uint32 tcv[4], tihv[4], tblock[16];	//cv37, cv38, cv39, cv40
	tcv[0] = cv[0] + 0x80000000;		//add type II difference
	tcv[1] = cv[1] + 0x80000000;
	tcv[2] = cv[2] + 0x80000000;
	tcv[3] = cv[3] + 0x80000000;
	memcpy(tblock, block, 64);	//copy message block
	//block difference 0, cover 1 case
	ReverseCompression(tihv, tcv, tblock);
	if(Equal(tihv, ihv)){
		return true;
	}
	int i = 0;	//temporary variable
	//block difference m11 = +2^0 to +2^31, cover 32 cases
	for(i = 0, tblock[11]++; i < 32; i++){	//initialize difference m11 = +2^0
		ReverseCompression(tihv, tcv, tblock);
		if(Equal(tihv, ihv)){
			return true;
		}
		tblock[11] += (0x00000001 << i);	//block difference m11 = +2^i, cover 1 case
	}
	//block difference m11 = -2^0 to -2^30, cover 31 cases
	for(i = 0, tblock[11] -= 0x80000001; i < 31; i++){	//initialize difference m11 = -2^0
		ReverseCompression(tihv, tcv, tblock);
		if(Equal(tihv, ihv)){
			return true;
		}
		tblock[11] -= (0x00000001 << i);	//block difference m11 = -2^i, cover 1 case
	}
	tblock[11] = block[11];	//eliminate difference of m11
	//block difference m4 = +2^20, cover 1 case
	tblock[4] += 0x00100000;
	ReverseCompression(tihv, tcv, tblock);
	if(Equal(tihv, ihv)){
		return true;
	}
	//block difference m4 = -2^20, cover 1 case
	tblock[4] -= 0x00200000;
	ReverseCompression(tihv, tcv, tblock);
	if(Equal(tihv, ihv)){
		return true;
	}
	//block difference m4 = +2^25, cover 1 case
	tblock[4] += 0x02100000;
	ReverseCompression(tihv, tcv, tblock);
	if(Equal(tihv, ihv)){
		return true;
	}
	//block difference m4 = -2^25, cover 1 case
	tblock[4] -= 0x04000000;
	ReverseCompression(tihv, tcv, tblock);
	if(Equal(tihv, ihv)){
		return true;
	}
	//block difference m4 = 2^31, cover 1 case
	tblock[4] += 0x82000000;
	ReverseCompression(tihv, tcv, tblock);
	if(Equal(tihv, ihv)){
		return true;
	}
	return false;
}
//implementation of DS2 Element, cover 3 case
bool DSFunction_2(const uint32 cv[], const uint32 ihv[], const uint32 block[]){
	uint32 tcv[4], tihv[4], tblock[16];	//cv37, cv38, cv39, cv40
	tcv[0] = cv[0] + 0x80000000;		//add type II difference
	tcv[1] = cv[1] + 0x80000000;
	tcv[2] = cv[2] + 0x80000000;
	tcv[3] = cv[3] + 0x80000000;
	memcpy(tblock, block, 64);	//copy message block
	//block difference m8 = 2^31, cover 1 case
	tblock[8] += 0x80000000;
	ReverseCompression(tihv, tcv, tblock);
	if(Equal(tihv, ihv)){
		return true;
	}
	//block difference m8 = 2^31, m11 = +2^21, cover 1 case
	tblock[11] += 0x00200000;
	ReverseCompression(tihv, tcv, tblock);
	if(Equal(tihv, ihv)){
		return true;
	}
	//block difference m8 = 2^31, m11 = -2^21, cover 1 case
	tblock[11] -= 0x00400000;
	ReverseCompression(tihv, tcv, tblock);
	if(Equal(tihv, ihv)){
		return true;
	}
	return false;
}
//implementation of DS3 Element, cover 2 cases
bool DSFunction_3(const uint32 cv[], const uint32 ihv[], const uint32 block[]){
	uint32 tcv[4], tihv[4], tblock[16];	//cv37, cv38, cv39, cv40
	tcv[0] = cv[0] + 0x80000000;		//add type II difference
	tcv[1] = cv[1] + 0x80000000;
	tcv[2] = cv[2] + 0x80000000;
	tcv[3] = cv[3] + 0x80000000;
	memcpy(tblock, block, 64);	//copy message block
	//block difference m5 = 2^31, cover 1 case
	tblock[5] += 0x80000000;
	ReverseCompression(tihv, tcv, tblock);
	if(Equal(tihv, ihv)){
		return true;
	}
	//block difference m5 = 2^31, m11 = 2^31, cover 1 case
	tblock[11] += 0x80000000;
	ReverseCompression(tihv, tcv, tblock);
	if(Equal(tihv, ihv)){
		return true;
	}
	return false;
}
//implementation of DS4 Element, cover 3 cases
bool DSFunction_4(const uint32 cv[], const uint32 ihv[], const uint32 block[]){
	uint32 tcv[4], tihv[4], tblock[16];	//cv37, cv38, cv39, cv40
	tcv[0] = cv[0] + 0x80000000;		//add type II difference
	tcv[1] = cv[1] + 0x80000000;
	tcv[2] = cv[2] + 0x80000000;
	tcv[3] = cv[3] + 0x80000000;
	memcpy(tblock, block, 64);	//copy message block
	//block difference m14 = 2^31, cover 1 case
	tblock[14] += 0x80000000;
	ReverseCompression(tihv, tcv, tblock);
	if(Equal(tihv, ihv)){
		return true;
	}
	//block difference m11 = +2^15, m4 = m14 = 2^31, cover 1 case
	tblock[4] += 0x80000000; 
	tblock[11] += 0x00008000;
	ReverseCompression(tihv, tcv, tblock);
	if(Equal(tihv, ihv)){
		return true;
	}
	//block difference m11 = -2^15, m4 = m14 = 2^31, cover 1 case
	tblock[11] -= 0x00010000;
	ReverseCompression(tihv, tcv, tblock);
	if(Equal(tihv, ihv)){
		return true;
	}
	return false;
}
//implementation of DS5 Element, cover 1 case
bool DSFunction_5(const uint32 cv[], const uint32 ihv[], const uint32 block[]){
	uint32 tcv[4], tihv[4], tblock[16];	//cv37, cv38, cv39, cv40
	tcv[0] = cv[0] + 0x80000000;		//add type II difference
	tcv[1] = cv[1] + 0x80000000;
	tcv[2] = cv[2] + 0x80000000;
	tcv[3] = cv[3] + 0x80000000;
	memcpy(tblock, block, 64);	//copy message block
	//block difference m5 = m8 = 2^31, cover 1 case
	tblock[5] += 0x80000000; 
	tblock[8] += 0x80000000;
	ReverseCompression(tihv, tcv, tblock);
	if(Equal(tihv, ihv)){
		return true;
	}
	return false;
}
//implementation of DS6 Element, cover 2 cases
bool DSFunction_6(const uint32 cv[], const uint32 ihv[], const uint32 block[]){
	uint32 tcv[4], tihv[4], tblock[16];
	tcv[0] = cv[0];		//copy cv to cv37, cv38, cv39, cv40
	tcv[1] = cv[1];
	tcv[2] = cv[2];
	tcv[3] = cv[3];
	memcpy(tblock, block, 64);	//copy message block
	//block difference m6 = +2^8, m9 = m15 = 2^31, cover 1 case
	tblock[6] += 0x00000100;
	tblock[9] += 0x80000000; 
	tblock[15] += 0x80000000;
	ReverseCompression(tihv, tcv, tblock);
	if(Equal(tihv, ihv)){
		return true;
	}
	//block difference m6 = -2^8, m9 = m15 = 2^31, cover 1 case
	tblock[6] -= 0x00000200;
	ReverseCompression(tihv, tcv, tblock);
	if(Equal(tihv, ihv)){
		return true;
	}
	return false;
}
//implementation of DS7 Element, cover 2 cases
bool DSFunction_7(const uint32 cv[], const uint32 ihv[], const uint32 block[]){
	uint32 tcv[4], tihv[4], tblock[16];	//cv37, cv38, cv39, cv40
	tcv[0] = cv[0];		//copy cv to cv37, cv38, cv39, cv40
	tcv[1] = cv[1];
	tcv[2] = cv[2];
	tcv[3] = cv[3];
	memcpy(tblock, block, 64);	//copy message block
	//block difference m9 = +2^27, m2 = m12 = 2^31, cover 1 case
	tblock[9] += 0x08000000;
	tblock[2] += 0x80000000; 
	tblock[12] += 0x80000000;
	ReverseCompression(tihv, tcv, tblock);
	if(Equal(tihv, ihv)){
		return true;
	}
	//block difference m9 = -2^27, m2 = m12 = 2^31, cover 1 case
	tblock[9] -= 0x10000000;
	ReverseCompression(tihv, tcv, tblock);
	if(Equal(tihv, ihv)){
		return true;
	}
	return false;
}
//implementation of DS8 Element, cover 2 cases
bool DSFunction_8(const uint32 cv[], const uint32 ihv[], const uint32 block[]){
	uint32 tcv[4], tihv[4], tblock[16];	//cv37, cv38, cv39, cv40
	tcv[0] = cv[0] + 0x80000000;		//add type II difference
	tcv[1] = cv[1] + 0x80000000;
	tcv[2] = cv[2] + 0x80000000;
	tcv[3] = cv[3] + 0x80000000;
	memcpy(tblock, block, 64);	//copy message block
	//block difference m4 = +2^20, m7 = m13 = 2^31, cover 1 case
	tblock[4] += 0x00100000;
	tblock[7] += 0x80000000; 
	tblock[13] += 0x80000000;
	ReverseCompression(tihv, tcv, tblock);
	if(Equal(tihv, ihv)){
		return true;
	}
	//block difference m4 = -2^20, m7 = m13 = 2^31, cover 1 case
	tblock[4] -= 0x00200000;
	ReverseCompression(tihv, tcv, tblock);
	if(Equal(tihv, ihv)){
		return true;
	}
	return false;
}
//implementation of DS9 Element, cover 4 cases
bool DSFunction_9(const uint32 cv[], const uint32 ihv[], const uint32 block[]){
	uint32 tcv[4], tihv[4], tblock[16];
	tcv[0] = cv[0];		//copy cv to cv37, cv38, cv39, cv40
	tcv[1] = cv[1];
	tcv[2] = cv[2];
	tcv[3] = cv[3];
	memcpy(tblock, block, 64);	//copy message block
	//block difference m2 = +2^8, m14 = 2^31, cover 1 case
	tblock[2] += 0x00000100;
	tblock[14] += 0x80000000; 
	ReverseCompression(tihv, tcv, tblock);
	if(Equal(tihv, ihv)){
		return true;
	}
	//block difference m2 = -2^8, m14 = 2^31, cover 1 case
	tblock[2] -= 0x00000200;
	ReverseCompression(tihv, tcv, tblock);
	if(Equal(tihv, ihv)){
		return true;
	}
	//block difference m2 = -2^8, m11 = -2^15, m4 = m14 = 2^31, cover 1 case
	tblock[4] += 0x80000000;
	tblock[11] -= 0x00008000;
	ReverseCompression(tihv, tcv, tblock);
	if(Equal(tihv, ihv)){
		return true;
	}
	//block difference m2 = +2^8, m11 = +2^15, m4 = m14 = 2^31, cover 1 case
	tblock[8] += 0x00000200;
	tblock[11] += 0x00010000;
	ReverseCompression(tihv, tcv, tblock);
	if(Equal(tihv, ihv)){
		return true;
	}
	return false;
}
//implementation of DS10 Element, cover 2 cases
bool DSFunction_10(const uint32 cv[], const uint32 ihv[], const uint32 block[]){
	uint32 tcv[4], tihv[4], tblock[16];
	tcv[0] = cv[0];		//copy cv to cv37, cv38, cv39, cv40
	tcv[1] = cv[1];
	tcv[2] = cv[2];
	tcv[3] = cv[3];
	memcpy(tblock, block, 64);	//copy message block
	//block difference m2 = +2^8, cover 1 case
	tblock[2] += 0x00000100;
	ReverseCompression(tihv, tcv, tblock);
	if(Equal(tihv, ihv)){
		return true;
	}
	//block difference m2 = -2^8, cover 1 case
	tblock[2] -= 0x00000200;
	ReverseCompression(tihv, tcv, tblock);
	if(Equal(tihv, ihv)){
		return true;
	}
	return false;
}
//implementation of DS11 Element, cover 2 cases
bool DSFunction_11(const uint32 cv[], const uint32 ihv[], const uint32 block[]){
	uint32 tcv[4], tihv[4], tblock[16];	//cv37, cv38, cv39, cv40
	tcv[0] = cv[0] + 0x80000000;		//add type II difference
	tcv[1] = cv[1] + 0x80000000;
	tcv[2] = cv[2] + 0x80000000;
	tcv[3] = cv[3] + 0x80000000;
	memcpy(tblock, block, 64);	//copy message block
	//block difference m8 = +2^25, cover 1 case
	tblock[8] += 0x02000000;
	ReverseCompression(tihv, tcv, tblock);
	if(Equal(tihv, ihv)){
		return true;
	}
	//block difference m8 = +2^25, cover 1 case
	tblock[8] -= 0x04000000;
	ReverseCompression(tihv, tcv, tblock);
	if(Equal(tihv, ihv)){
		return true;
	}
	return false;
}
//implementation of DS12 Element, cover 2 cases
bool DSFunction_12(const uint32 cv[], const uint32 ihv[], const uint32 block[]){
	uint32 tcv[4], tihv[4], tblock[16];
	tcv[0] = cv[0];		//copy cv to cv37, cv38, cv39, cv40
	tcv[1] = cv[1];
	tcv[2] = cv[2];
	tcv[3] = cv[3];
	memcpy(tblock, block, 64);	//copy message block
	//block difference m14 = +2^16, cover 1 case
	tblock[14] += 0x00010000;
	ReverseCompression(tihv, tcv, tblock);
	if(Equal(tihv, ihv)){
		return true;
	}
	//block difference m14 = -2^16, cover 1 case
	tblock[14] -= 0x00020000;
	ReverseCompression(tihv, tcv, tblock);
	if(Equal(tihv, ihv)){
		return true;
	}
	return false;
}
//implementation of DS13 Element, cover 6 cases
bool DSFunction_13(const uint32 cv[], const uint32 ihv[], const uint32 block[]){
	uint32 tcv[4], tihv[4], tblock[16];
	tcv[0] = cv[0];		//copy cv to cv37, cv38, cv39, cv40
	tcv[1] = cv[1];
	tcv[2] = cv[2];
	tcv[3] = cv[3];
	memcpy(tblock, block, 64);	//copy message block
	//block difference m5 = +2^10, cover 1 case
	tblock[5] += 0x00000400;
	ReverseCompression(tihv, tcv, tblock);
	if(Equal(tihv, ihv)){
		return true;
	}
	//block difference m5 = -2^10, cover 1 case
	tblock[5] -= 0x00000800;
	ReverseCompression(tihv, tcv, tblock);
	if(Equal(tihv, ihv)){
		return true;
	}
	//block difference m5 = -2^10, m11 = -2^21, cover 1 case
	tblock[11] -= 0x00200000;
	ReverseCompression(tihv, tcv, tblock);
	if(Equal(tihv, ihv)){
		return true;
	}
	//block difference m5 = +2^10, m11 = +2^21, cover 1 case
	tblock[5] += 0x00000800;
	tblock[11] += 0x00400000;
	ReverseCompression(tihv, tcv, tblock);
	if(Equal(tihv, ihv)){
		return true;
	}
	//block difference m5 = +2^10, m11 = 2^31, cover 1 case
	tblock[11] += 0x7FE00000;
	ReverseCompression(tihv, tcv, tblock);
	if(Equal(tihv, ihv)){
		return true;
	}
	//block difference m5 = -2^10, m11 = 2^31, cover 1 case
	tblock[5] -= 0x00000800;
	ReverseCompression(tihv, tcv, tblock);
	if(Equal(tihv, ihv)){
		return true;
	}
	return false;
}
//implementation of DS14 Element, cover 2 cases
bool DSFunction_14(const uint32 cv[], const uint32 ihv[], const uint32 block[]){
	uint32 tcv[4], tihv[4], tblock[16];
	tcv[0] = cv[0];		//copy cv to cv37, cv38, cv39, cv40
	tcv[1] = cv[1];
	tcv[2] = cv[2];
	tcv[3] = cv[3];
	memcpy(tblock, block, 64);	//copy message block
	//block difference m5 = +2^10, m10 = 2^31, cover 1 case
	tblock[5] += 0x00000400;
	tblock[10] += 0x80000000;
	ReverseCompression(tihv, tcv, tblock);
	if(Equal(tihv, ihv)){
		return true;
	}
	//block difference m5 = -2^10, m10 = 2^31, cover 1 case
	tblock[5] -= 0x00000800;
	ReverseCompression(tihv, tcv, tblock);
	if(Equal(tihv, ihv)){
		return true;
	}
	return false;
}

/* Distinguishable Set Check Algorithm */
bool DistinguishableSetCheckAlgorithm(const uint32 ihv[], const uint32 cv[], const uint32 scv[], const uint32 block[]){
	bool isCollisionBlock = false;
	int col = scv[0] & 0x00000003;	//key bits, the least 2 bits of scv[0]
	for(int i = 0; i < 14; i++){
		if(distinguishableSet[i][col] == (scv[0] & distinguishableSet[i][4])){	//find a candidate DS Element 
			switch(i){		//Entry of DS Element
				case 0: isCollisionBlock = DSFunction_1(cv, ihv, block); break;
				case 1: isCollisionBlock = DSFunction_2(cv, ihv, block); break;
				case 2: isCollisionBlock = DSFunction_3(cv, ihv, block); break;
				case 3: isCollisionBlock = DSFunction_4(cv, ihv, block); break;
				case 4: isCollisionBlock = DSFunction_5(cv, ihv, block); break;
				case 5: isCollisionBlock = DSFunction_6(cv, ihv, block); break;
				case 6: isCollisionBlock = DSFunction_7(cv, ihv, block); break;
				case 7: isCollisionBlock = DSFunction_8(cv, ihv, block); break;
				case 8: isCollisionBlock = DSFunction_9(cv, ihv, block); break;
				case 9: isCollisionBlock = DSFunction_10(cv, ihv, block); break;
				case 10: isCollisionBlock = DSFunction_11(cv, ihv, block); break;
				case 11: isCollisionBlock = DSFunction_12(cv, ihv, block); break;
				case 12: isCollisionBlock = DSFunction_13(cv, ihv, block); break;
				case 13: isCollisionBlock = DSFunction_14(cv, ihv, block); break;
				default: break;
			}
			if(isCollisionBlock){	//find a collision block
				return true;
			}
		}
	}
	return false;
}
/* Individual Checked Set Check Algorithm */
bool IndividualSetCheckAlgorithm(const uint32 ihv[], const uint32 cv[], const uint32 scv[], const uint32 block[]){
	uint32 tcv[4], tihv[4], tblock[16];
	uint16 col = 0, auxcol = 0;
	tcv[0] = cv[0];		//copy cv to cv37, cv38, cv39, cv40
	tcv[1] = cv[1];
	tcv[2] = cv[2];
	tcv[3] = cv[3];
	//ICS1 Element Check, cover 2 cases
	col = scv[2] & (0x00000003);	//key bits, the least 2 bits of scv[2]
	if(individualCheckedSet[0][col] == (scv[2] & individualCheckedSet[0][4])){
		memcpy(tblock, block, 64);	//copy block to temporary variables
		//block difference m4 = +2^20, m7 = m13 = 2^31, cover 1 case
		tblock[4] += 0x00100000;
		tblock[7] += 0x80000000;
		tblock[13] += 0x80000000;
		ReverseCompression(tihv, tcv, tblock);
		if(Equal(tihv, ihv)){
			return true;
		}
		//block difference m4 = -2^20, m7 = m13 = 2^31, cover 1 case
		tblock[4] -= 0x00200000;
		ReverseCompression(tihv, tcv, tblock);
		if(Equal(tihv, ihv)){
			return true;
		}
	}
	//ICS2 Element Check, cover 3 cases
	col = scv[3] & (0x00000003);	//key bits, the least 2 bits of scv[3]
	if(individualCheckedSet[1][col] == (scv[3] & individualCheckedSet[1][4])){
		memcpy(tblock, block, 64);	//copy block to temporary variables
		//block difference m14 = 2^31, cover 1 case
		tblock[14] += 0x80000000;
		ReverseCompression(tihv, tcv, tblock);
		if(Equal(tihv, ihv)){
			return true;
		}
		//block difference m11 = +2^15, m4 = m14 = 2^31, cover 1 case
		tblock[11] += 0x00008000;
		tblock[4] += 0x80000000;
		ReverseCompression(tihv, tcv, tblock);
		if(Equal(tihv, ihv)){
			return true;
		}
		//block difference m11 = -2^15, m4 = m14 = 2^31, cover 1 case
		tblock[11] -= 0x00010000;
		ReverseCompression(tihv, tcv, tblock);
		if(Equal(tihv, ihv)){
			return true;
		}
	}
	//ICS3 Element Check, cover 3 cases
	col = scv[4] & (0x00000003);	//key bits, the least 2 bits of scv[4]
	if(individualCheckedSet[2][col] == (scv[4] & individualCheckedSet[2][4])){
		memcpy(tblock, block, 64);	//copy block to temporary variables
		//block difference m5 = 2^31, cover 1 case
		tblock[5] += 0x80000000;
		ReverseCompression(tihv, tcv, tblock);
		if(Equal(tihv, ihv)){
			return true;
		}
		//block difference m5 = 2^31, m11 = 2^31, cover 1 case
		tblock[11] += 0x80000000;
		ReverseCompression(tihv, tcv, tblock);
		if(Equal(tihv, ihv)){
			return true;
		}
		//block difference m5 = 2^31, m8 = 2^31, cover 1 case
		tblock[8] += 0x80000000;
		tblock[11] -= 0x80000000;
		ReverseCompression(tihv, tcv, tblock);
		if(Equal(tihv, ihv)){
			return true;
		}
	}
	//add type II difference
	tcv[0] += 0x80000000;
	tcv[1] += 0x80000000;
	tcv[2] += 0x80000000;
	tcv[3] += 0x80000000;
	//ICS4 Element Check, cover 2 cases
	col = (scv[0] >> 8) & (0x00000003);	//key bits are cv49[31], cv50[31]
	if(individualCheckedSet[3][col] == (scv[0] & individualCheckedSet[3][4])){
		memcpy(tblock, block, 64);	//copy message block
		//block difference m5 = +2^10, m10 = 2^31, cover 1 case
		tblock[5] += 0x00000400;
		tblock[10] += 0x80000000;
		ReverseCompression(tihv, tcv, tblock);
		if(Equal(tihv, ihv)){
			return true;
		}
		//block difference m5 = -2^10, m10 = 2^31, cover 1 case
		tblock[5] -= 0x00000800;
		ReverseCompression(tihv, tcv, tblock);
		if(Equal(tihv, ihv)){
			return true;
		}
	}
	//ICS5 Element Check, cover 2 cases
	col = scv[1] & (0x00000003);	//key bits, the least 2 bits of scv[1]
	if(individualCheckedSet[4][col] == (scv[1] & individualCheckedSet[4][4])){
		memcpy(tblock, block, 64);	//copy message block
		//block difference m9 = +2^27, m2 = m12 = 2^31, cover 1 case
		tblock[2] += 0x80000000;
		tblock[9] += 0x08000000;
		tblock[12] += 0x80000000;
		ReverseCompression(tihv, tcv, tblock);
		if(Equal(tihv, ihv)){
			return true;
		}
		//block difference m9 = -2^27, m2 = m12 = 2^31, cover 1 case
		tblock[9] -= 0x10000000;
		ReverseCompression(tihv, tcv, tblock);
		if(Equal(tihv, ihv)){
			return true;
		}
	}
	//ICS6 Element Check, cover 2 cases
	auxcol = scv[3] & (0x00000003);		//auxiliary key bits, the least 2 bits of scv[3]
	if(((scv[0] & 0x0C00) == 0x0800) && (individualCheckedSet[5][auxcol] == (scv[3] & individualCheckedSet[5][4]))){
		memcpy(tblock, block, 64);	//copy message block
		//block difference m2 = +2^8, cover 1 case
		tblock[2] += 0x00000100;
		ReverseCompression(tihv, tcv, tblock);
		if(Equal(tihv, ihv)){
			return true;
		}
		//block difference m2 = -2^8, cover 1 case
		tblock[2] -= 0x00000200;
		ReverseCompression(tihv, tcv, tblock);
		if(Equal(tihv, ihv)){
			return true;
		}
	}
	//ICS7 Element Check, cover 2 cases
	col = (scv[0] >> 9) & (0x00000003);	//main key bits are cv48[31], cv49[31]
	auxcol = scv[2] & (0x00000003);		//auxiliary key bits, the least 2 bits of scv[2]
	if( (individualCheckedSet[6][col] == (scv[0] & individualCheckedSet[6][4])) 
	 && (individualCheckedSet[7][auxcol] == (scv[2] & individualCheckedSet[7][4]))){
		memcpy(tblock, block, 64);	//copy message block
		//block difference m14 = +2^16, cover 1 case
		tblock[14] += 0x00010000;
		ReverseCompression(tihv, tcv, tblock);
		if(Equal(tihv, ihv)){
			return true;
		}
		//block difference m14 = -2^16, cover 1 case
		tblock[14] -= 0x00020000;
		ReverseCompression(tihv, tcv, tblock);
		if(Equal(tihv, ihv)){
			return true;
		}
	}
	//ICS8 Element Check, cover 6 cases
	col = (scv[0] >> 8) & (0x00000003);	//main key bits are cv49[31], cv50[31]
	auxcol = scv[3] & (0x00000003);		//auxiliary key bits, the least 2 bits of scv[3]
	if( (individualCheckedSet[8][col] == (scv[0] & individualCheckedSet[8][4])) 
	 && (individualCheckedSet[9][auxcol] == (scv[3] & individualCheckedSet[9][4]))){
		memcpy(tblock, block, 64);	//copy message block
		//block difference m5 = +2^10, cover 1 case
		tblock[5] += 0x00000400;
		ReverseCompression(tihv, tcv, tblock);
		if(Equal(tihv, ihv)){
			return true;
		}
		//block difference m5 = -2^10, cover 1 case
		tblock[5] -= 0x00000800;
		ReverseCompression(tihv, tcv, tblock);
		if(Equal(tihv, ihv)){
			return true;
		}
		//block difference m5 = -2^10, m11 = -2^21, cover 1 case
		tblock[11] -= 0x00200000;
		ReverseCompression(tihv, tcv, tblock);
		if(Equal(tihv, ihv)){
			return true;
		}
		//block difference m5 = +2^10, m11 = +2^21, cover 1 case
		tblock[5] += 0x00000800;
		tblock[11] += 0x00400000;
		ReverseCompression(tihv, tcv, tblock);
		if(Equal(tihv, ihv)){
			return true;
		}
		//block difference m5 = +2^10, m11 = 2^31, cover 1 case
		tblock[11] += 0x7FE00000;
		ReverseCompression(tihv, tcv, tblock);
		if(Equal(tihv, ihv)){
			return true;
		}
		//block difference m5 = -2^10, m11 = 2^31, cover 1 case
		tblock[5] -= 0x00000800;
		ReverseCompression(tihv, tcv, tblock);
		if(Equal(tihv, ihv)){
			return true;
		}
	}
	return false;
}
/* Non-Distinguishable Set Check Algorithm */
bool NonDistinguishableSetCheckAlgorithm(const uint32 ihv[], const uint32 cv[], const uint32 scv[], const uint32 block[]){
	uint32 tcv[4], tihv[4], tblock[16];
	tcv[0] = cv[0];		//copy cv to cv37, cv38, cv39, cv40
	tcv[1] = cv[1];
	tcv[2] = cv[2];
	tcv[3] = cv[3];
	memcpy(tblock, block, 64);	//copy message block
	int i = 0;	//temporary variable
	//block difference m11 = +2^0 to +2^31, cover 32 cases
	for(i = 0, tblock[11]++; i < 32; i++){	//initialize difference m11 = +2^0
		ReverseCompression(tihv, tcv, tblock);
		if(Equal(tihv, ihv)){
			return true;
		}
		tblock[11] += (0x00000001 << i);	//block difference m11 = +2^i, cover 1 case
	}
	//block difference m11 = -2^0 to -2^30, cover 31 cases
	for(i = 0, tblock[11] -= 0x80000001; i < 31; i++){	//initialize difference m11 = -2^0
		ReverseCompression(tihv, tcv, tblock);
		if(Equal(tihv, ihv)){
			return true;
		}
		tblock[11] -= (0x00000001 << i);	//block difference m11 = -2^i, cover 1 case
	}
	tblock[11] = block[11];	//eliminate difference of m11
	//block difference m4 = +2^20, cover 1 case
	tblock[4] += 0x00100000;
	ReverseCompression(tihv, tcv, tblock);
	if(Equal(tihv, ihv)){
		return true;
	}
	//block difference m4 = -2^20, cover 1 case
	tblock[4] -= 0x00200000;
	ReverseCompression(tihv, tcv, tblock);
	if(Equal(tihv, ihv)){
		return true;
	}
	//block difference m4 = +2^25, cover 1 case
	tblock[4] += 0x02100000;
	ReverseCompression(tihv, tcv, tblock);
	if(Equal(tihv, ihv)){
		return true;
	}
	//block difference m4 = -2^25, cover 1 case
	tblock[4] -= 0x04000000;
	ReverseCompression(tihv, tcv, tblock);
	if(Equal(tihv, ihv)){
		return true;
	}
	//block difference m4 = 2^31, cover 1 case
	tblock[4] += 0x82000000;
	ReverseCompression(tihv, tcv, tblock);
	if(Equal(tihv, ihv)){
		return true;
	}
	tblock[4] = block[4];	//eliminate difference of m4
	//block difference m8 = +2^25, cover 1 case
	tblock[8] += 0x02000000;
	ReverseCompression(tihv, tcv, tblock);
	if(Equal(tihv, ihv)){
		return true;
	}
	//block difference m8 = -2^25, cover 1 case
	tblock[8] -= 0x04000000;
	ReverseCompression(tihv, tcv, tblock);
	if(Equal(tihv, ihv)){
		return true;
	}
	//block difference m8 = 2^31, cover 1 case
	tblock[8] += 0x82000000;
	ReverseCompression(tihv, tcv, tblock);
	if(Equal(tihv, ihv)){
		return true;
	}
	//block difference m8 = 2^31, m11 = +2^21, cover 1 case
	tblock[11] += 0x00200000;
	ReverseCompression(tihv, tcv, tblock);
	if(Equal(tihv, ihv)){
		return true;
	}
	//block difference m8 = 2^31, m11 = -2^21, cover 1 case
	tblock[11] -= 0x00400000;
	ReverseCompression(tihv, tcv, tblock);
	if(Equal(tihv, ihv)){
		return true;
	}
	tblock[8] -= 0x80000000;	//eliminate difference of m8 and m11
	tblock[11] += 0x00200000;
	//add type II difference
	tcv[0] += 0x80000000;
	tcv[1] += 0x80000000;
	tcv[2] += 0x80000000;
	tcv[3] += 0x80000000;
	//block difference m2 = +2^8, m14 = 2^31, cover 1 case
	tblock[2] += 0x00000100;
	tblock[14] += 0x80000000;
	ReverseCompression(tihv, tcv, tblock);
	if(Equal(tihv, ihv)){
		return true;
	}
	//block difference m2 = -2^8, m14 = 2^31, cover 1 case
	tblock[2] -= 0x00000200;
	ReverseCompression(tihv, tcv, tblock);
	if(Equal(tihv, ihv)){
		return true;
	}
	//block difference m2 = -2^8, m11 = -2^15, m4 = m14 = 2^31, cover 1 case
	tblock[11] -= 0x00008000;
	tblock[4] += 0x80000000;
	ReverseCompression(tihv, tcv, tblock);
	if(Equal(tihv, ihv)){
		return true;
	}
	//block difference m2 = +2^8, m11 = +2^15, m4 = m14 = 2^31, cover 1 case
	tblock[2] += 0x00000200;
	tblock[11] += 0x00010000;
	ReverseCompression(tihv, tcv, tblock);
	if(Equal(tihv, ihv)){
		return true;
	}
	tblock[2] -= 0x00000100;	//eliminate difference of m2, m4, m11 and m14
	tblock[4] -= 0x80000000;
	tblock[11] -= 0x00008000;
	tblock[14] -= 0x80000000;
	//block difference m6 = +2^8, m9 = m15 = 2^31, cover 1 case
	tblock[6] += 0x00000100;
	tblock[9] += 0x80000000;
	tblock[15] += 0x80000000;
	ReverseCompression(tihv, tcv, tblock);
	if(Equal(tihv, ihv)){
		return true;
	}
	//block difference m6 = -2^8, m9 = m15 = 2^31, cover 1 case
	tblock[6] -= 0x00000200;
	ReverseCompression(tihv, tcv, tblock);
	if(Equal(tihv, ihv)){
		return true;
	}
	return false;
}
bool SetCheckAlgorithm(const uint32 ihv[], const uint32 cv[], const uint32 scv[], const uint32 block[]){
	if(DistinguishableSetCheckAlgorithm(ihv, cv, scv, block)){	//check Distinguishable Set
		return true;
	}
	if(IndividualSetCheckAlgorithm(ihv, cv, scv, block)){		//check Individual Checked Set
		return true;
	}
	if(NonDistinguishableSetCheckAlgorithm(ihv, cv, scv, block)){	//check Non-Distinguishable Set
		return true;
	}
}
/* Correct Check Algorithm, all published differences are checked */
void CorrectCheckAlgorithm(){
	uint32 ihv[4],cv[4], scv[5] ={0};
	//Reference 4, block difference is m11 = -2^15, m4 = m14 = 2^31
	ihv[0] = 0x67452301, ihv[1] = 0xefcdab89, ihv[2] = 0x98badcfe, ihv[3] = 0x10325476;	//iv 0
	uint32 b11_ref4[] =  {0x2dd31d1, 0xc4eee6c5, 0x69a3d69, 0x5cf9af98, 0x87b5ca2f, 0xab7e4612, 0x3e580440, 0x897ffbb8, 
						  0x634ad55, 0x2b3f409, 0x8388e483, 0x5a417125, 0xe8255108, 0x9fc9cdf7, 0xf2bd1dd9, 0x5b3c3780};
	uint32 b12_ref4[] =  {0xd11d0b96, 0x9c7b41dc, 0xf497d8e4, 0xd555655a, 0xc79a7335, 0xcfdebf0, 0x66f12930, 0x8fb109d1, 
						  0x797f2775, 0xeb5cd530, 0xbaade822, 0x5c15cc79, 0xddcb74ed, 0x6dd3c55f, 0xd80a9bb1, 0xe3a7cc35};
	Compression(ihv, b11_ref4);
	Compression_Modify(ihv, cv, scv, b12_ref4);	//compress a block, output chaining values cv and sufficient condition vector
	if(SetCheckAlgorithm(ihv, cv, scv, b12_ref4)){
		cout<<"ref  4 is OK, difference is m11 = -2^15, m4 = m14 = 2^31."<<endl;
	}
	//Reference 4, block difference is m11 = +2^15, m4 = m14 = 2^31
	ihv[0] = 0x67452301, ihv[1] = 0xefcdab89, ihv[2] = 0x98badcfe, ihv[3] = 0x10325476;	//iv 0
	uint32 b21_ref4[] =  {0x2dd31d1, 0xc4eee6c5, 0x69a3d69, 0x5cf9af98, 0x7b5ca2f, 0xab7e4612, 0x3e580440, 0x897ffbb8, 
						  0x634ad55, 0x2b3f409, 0x8388e483, 0x5a41f125, 0xe8255108, 0x9fc9cdf7, 0x72bd1dd9, 0x5b3c3780};
	uint32 b22_ref4[] =  {0xd11d0b96, 0x9c7b41dc, 0xf497d8e4, 0xd555655a, 0x479a7335, 0xcfdebf0, 0x66f12930, 0x8fb109d1, 
						  0x797f2775, 0xeb5cd530, 0xbaade822, 0x5c154c79, 0xddcb74ed, 0x6dd3c55f, 0x580a9bb1, 0xe3a7cc35};
	Compression(ihv, b21_ref4);
	Compression_Modify(ihv, cv, scv, b22_ref4);	//compress a block, output chaining values cv and sufficient condition vector
	if(SetCheckAlgorithm(ihv, cv, scv, b22_ref4)){
		cout<<"ref  4 is OK, difference is m11 = +2^15, m4 = m14 = 2^31."<<endl;
	}
	//Refer5 and Sasaki' work, block difference is m11 = 2^31
	ihv[0] = 0x67452301, ihv[1] = 0xefcdab89, ihv[2] = 0x98badcfe, ihv[3] = 0x10325476;	//iv 0
	uint32 b11_ref21[] = {0x3938313c, 0x37322d34, 0x332d3635, 0x2e383933, 0x37373936, 0x3433302d, 0x38312d35, 0x61704035, 
						  0x6f777373, 0x645f6472, 0x63657465, 0x5f726f74, 0x2e636264, 0x6976746d, 0x632e7765, 0x73752e61};
	uint32 b12_ref21[] = {0x986e1da4, 0x83707d06, 0xa86e1ddd, 0xe264eedb, 0xff68e19f, 0x120ea5b3, 0x7437d3e2, 0x600f543d,
						  0x7c63c5ab, 0xe9ead9d9, 0xa9b5c51e, 0xc309f623, 0xfd534f1e, 0xad33c7ad, 0xfd0380c6, 0x7745f36a};
	uint32 b13_ref21[] = {0x6cbebe2c, 0x539e4d17, 0x6f342bd1, 0x78e2b4e9, 0xef5d9c25, 0xe02bd34e, 0x774d98bd, 0x1f7b0622,
						  0x4342413e, 0x47464544, 0x4b4a4948, 0x4f4e4d4c, 0x53525150, 0x57565554, 0x305a5958, 0x33333231};
	Compression(ihv, b11_ref21);
	Compression(ihv, b12_ref21);
	Compression_Modify(ihv, cv, scv, b13_ref21);	//compress a block, output chaining values cv and sufficient condition vector
	if(SetCheckAlgorithm(ihv, cv, scv, b13_ref21)){
		cout<<"ref  5 and Sasaki' work is OK, difference is m11 = 2^31."<<endl;
	}
	//Reference 6, block difference is m2 = -2^8, m11 = -2^15, m4 = m14 = 2^31
	ihv[0] = 0x67452301, ihv[1] = 0xefcdab89, ihv[2] = 0x98badcfe, ihv[3] = 0x10325476;	//iv 0
	uint32 b11_ref6[] =  {0x6465644f, 0x6c6f4720, 0x69657264, 0x4f0a6863, 0x20646564, 0x646c6f47, 0x63696572, 0x644f0a68, 
				          0x47206465, 0x72646c6f, 0x68636965, 0x65644f0a, 0x6f472064, 0x000d05d8, 0x1893bb19, 0x96aa4c92};
	uint32 b12_ref6[] =  {0xb85ce3dc, 0xe149b335, 0x508ce944, 0x61f42cc2, 0x64404a24, 0xecfa1abf, 0x420d82c5, 0x6b8dd38a, 
					      0xada589ec, 0x6390e251, 0x6cb179dd, 0x97127cf6, 0xaff54786, 0xace33d12, 0x5c0844f8, 0x56b925d0};
	Compression(ihv, b11_ref6);
	Compression_Modify(ihv, cv, scv, b12_ref6);	//compress a block, output chaining values cv and sufficient condition vector
	if(SetCheckAlgorithm(ihv, cv, scv, b12_ref6)){
		cout<<"ref  6 is OK, difference is m2 = -2^8, m11 = -2^15, m4 = m14 = 2^31."<<endl;
	}
	//Reference 6, block difference is m2 = +2^8, m11 = +2^15, m4 = m14 = 2^31
	ihv[0] = 0x67452301, ihv[1] = 0xefcdab89, ihv[2] = 0x98badcfe, ihv[3] = 0x10325476;	//iv 0
	uint32 b21_ref6[] =  {0x6c61654e, 0x626f4b20, 0x7a74696c, 0x61654e0a, 0x6f4b206c, 0x74696c62, 0x654e0a7a, 0x4b206c61, 
						  0x696c626f, 0x4e0a7a74, 0x206c6165, 0x6c626f4b, 0x0a7a7469, 0x000eb875, 0xc9d2f335, 0xad1baf09};
	uint32 b22_ref6[] =  {0xb85ce3dc, 0xe149b335, 0x508ce844, 0x61f42cc2, 0xe4404a24, 0xecfa1abf, 0x420d82c5, 0x6b8dd38a, 
					      0xada589ec, 0x6390e251, 0x6cb179dd, 0x9711fcf6, 0xaff54786, 0xace33d12, 0xdc0844f8, 0x56b925d0};
	Compression(ihv, b21_ref6);
	Compression_Modify(ihv, cv, scv, b22_ref6);	//compress a block, output chaining values cv and sufficient condition vector
	if(SetCheckAlgorithm(ihv, cv, scv, b22_ref6)){
		cout<<"ref  6 is OK, difference is m2 = +2^8, m11 = +2^15, m4 = m14 = 2^31."<<endl;
	}
	//Reference 16, block difference is 0
	ihv[0] = 0x399e49d4, ihv[1] = 0x876c9442, ihv[2] = 0xf7dfe793, ihv[3] = 0x83d49001;	//ihv 1
//	ihv[0] = 0xb99e49d4, ihv[1] = 0x076c9442, ihv[2] = 0x77dfe793, ihv[3] = 0x03d49001;	//ihv 2
	uint32 b11_ref16[] = {0x5ffbb485, 0xb73256d8, 0x19df08e4, 0x11054a66, 0x22c00e98, 0x450a05c4, 0x5f53a940, 0x9ddc1cf8,
						  0xdadab3db, 0x8a43597a, 0x4ca51993, 0xe7db12e5, 0x1f1c0317, 0x9a3baad6, 0xb275b7bb, 0x0f09cfd5};
	Compression_Modify(ihv, cv, scv, b11_ref16);	//compress a block, output chaining values cv and sufficient condition vector
	if(SetCheckAlgorithm(ihv, cv, scv, b11_ref16)){
		cout<<"ref 16 is OK, difference is 0."<<endl;
	}
	//Reference 17, block difference is m5 = -2^10, m10 = 2^31
	ihv[0] = 0x67452301, ihv[1] = 0xefcdab89, ihv[2] = 0x98badcfe, ihv[3] = 0x10325476;	//iv 0
	uint32 b21_ref17[] = {0x6165300e, 0x87a79a55, 0xf7c60bd0, 0x34febd0b, 0x6503cf04, 0x854f749e, 0xfb0fc034, 0x874c9c65,
						  0x2f94cc40, 0x15a12deb, 0xdc15f4a3, 0x490786bb, 0x6d658673, 0xa4341f7d, 0x8fd75920, 0xefd18d5a};
	Compression_Modify(ihv, cv, scv, b21_ref17);	//compress a block, output chaining values cv and sufficient condition vector
	if(SetCheckAlgorithm(ihv, cv, scv, b21_ref17)){
		cout<<"ref 17 is OK, difference is m5 = -2^10, m10 = 2^31."<<endl;
	}
	//Reference 17, block difference is m5 = +2^10, m10 = 2^31
	ihv[0] = 0x67452301, ihv[1] = 0xefcdab89, ihv[2] = 0x98badcfe, ihv[3] = 0x10325476;	//iv 0
	uint32 b11_ref17[] = {0x6165300e, 0x87a79a55, 0xf7c60bd0, 0x34febd0b, 0x6503cf04, 0x854f709e, 0xfb0fc034, 0x874c9c65,
						  0x2f94cc40, 0x15a12deb, 0x5c15f4a3, 0x490786bb, 0x6d658673, 0xa4341f7d, 0x8fd75920, 0xefd18d5a};
	Compression_Modify(ihv, cv, scv, b11_ref17);	//compress a block, output chaining values cv and sufficient condition vector
	if(SetCheckAlgorithm(ihv, cv, scv, b11_ref17)){
		cout<<"ref 17 is OK, difference is m5 = +2^10, m10 = 2^31."<<endl;
	}
	//Reference 18, block difference is m6 = -2^8, m9 = m15 = 2^31
	ihv[0] = 0x67452301, ihv[1] = 0xefcdab89, ihv[2] = 0x98badcfe, ihv[3] = 0x10325476;	//iv 0
	uint32 b21_ref18[] = {0x9d133b36, 0xec2a44c9, 0x7e32bcdd, 0x5498e911, 0x78b8c3b6, 0x1a629661, 0xb456c37f, 0xccec27cb,
						  0x7c1eede2, 0x53934205, 0xfa24921c, 0x3bb373cc, 0xaabfa31, 0xa7bc4d44, 0xba91559, 0xd67d9653};
	uint32 b22_ref18[] = {0x1522683e, 0x3e598084, 0xbc74fad, 0x854881fa, 0xcec6c0fb, 0x9ee808b5, 0x1acbeaf8, 0xe77779b2,
						  0xc81afd90, 0x285ec52a, 0x6d16ba45, 0x629b30e8, 0x6e00673, 0xa232e472, 0xedcaac9, 0x37d754f6};
	Compression(ihv, b21_ref18);
	Compression_Modify(ihv, cv, scv, b22_ref18);	//compress a block, output chaining values cv and sufficient condition vector
	if(SetCheckAlgorithm(ihv, cv, scv, b22_ref18)){
		cout<<"ref 18 is OK, difference is m6 = -2^8, m9 = m15 = 2^31."<<endl;
	}
	//Reference 18, block difference is m6 = +2^8, m9 = m15 = 2^31
	ihv[0] = 0x67452301, ihv[1] = 0xefcdab89, ihv[2] = 0x98badcfe, ihv[3] = 0x10325476;	//iv 0
	uint32 b11_ref18[] = {0x9d133b36, 0xec2a44c9, 0x7e32bcdd, 0x5498e911, 0x78b8c3b6, 0x1a629661, 0xb456c47f, 0xccec27cb,
						  0x7c1eede2, 0xd3934205, 0xfa24921c, 0x3bb373cc, 0x0aabfa31, 0xa7bc4d44, 0xba91559, 0x567d9653};
	uint32 b12_ref18[] = {0x1522683e, 0x3e598084, 0xbc74fad, 0x854881fa, 0xcec6c0fb, 0x9ee808b5, 0x1acbe9f8, 0xe77779b2,
					      0xc81afd90, 0xa85ec52a, 0x6d16ba45, 0x629b30e8, 0x6e00673, 0xa232e472, 0xedcaac9, 0xb7d754f6};
	Compression(ihv, b11_ref18);
	Compression_Modify(ihv, cv, scv, b12_ref18);	//compress a block, output chaining values cv and sufficient condition vector
	if(SetCheckAlgorithm(ihv, cv, scv, b12_ref18)){
		cout<<"ref 18 is OK, difference is m6 = +2^8, m9 = m15 = 2^31."<<endl;
	}
	//Reference 19, block difference is m8 = 2^31(first block, second difference is 0, the same to Reference 16)
	ihv[0] = 0x67452301, ihv[1] = 0xefcdab89, ihv[2] = 0x98badcfe, ihv[3] = 0x10325476;	//iv 0
	uint32 b11_ref19[] = {0x68106ac6, 0x2094ed6b, 0xa3ec34eb, 0xf4383dff, 0x157fe4d, 0xeff04e4e, 0x1119f00b, 0x22172e32,
					      0xc55102b0, 0x99355658, 0x97874ee2, 0x2c408161, 0xf55b1a3f, 0x31e6ad3c, 0x6ed9a43b, 0x4116f7b6};
	uint32 b12_ref19[] = {0xec434329, 0xccab7e9a, 0x32b86260, 0x82c53b56, 0xad5ff512, 0xedeab6b5, 0x3e2c15ea, 0x4a564948,
						  0x292cf96c, 0x684ad345, 0x63cb649d, 0xc2b7e49e, 0xa7cfd089, 0x127c0548, 0xc2906aa4, 0x66e94d25};
	Compression(ihv, b11_ref19);
	Compression_Modify(ihv, cv, scv, b12_ref19);	//compress a block, output chaining values cv and sufficient condition vector
	if(SetCheckAlgorithm(ihv, cv, scv, b12_ref19)){
		cout<<"ref 19 is OK, difference is m8 = 2^31."<<endl;
	}
	//Reference 20, block difference is m9 = -2^27, m2 = m12 = 2^31
	ihv[0] = 0x67452301, ihv[1] = 0xefcdab89, ihv[2] = 0x98badcfe, ihv[3] = 0x10325476;	//iv 0
	uint32 b21_ref20[] = {0xce7e83ca, 0xcade345e, 0xb81d83a5, 0x562edf19, 0xb93c9d41, 0xf9c4e244, 0x5b9b832f, 0xe16d2fe5, 
						  0x4b286759, 0xf9fe0301, 0xa912ef12, 0x95a85769, 0x18adf66c, 0x8b1ad802, 0x291b44ab, 0x732af6a2};
	uint32 b22_ref20[] = {0x6a9b0d7d, 0x9aaeeda9, 0x62255628, 0xb6a85040, 0xc7e08fd1, 0x077e530a, 0xdedd6809, 0xd20a7d80, 
						  0x55dfbe93, 0x78571c29, 0xc13d746c, 0x062792c8, 0x45a152ce, 0x69727500, 0x351ec8f7, 0xcfffaf73};
	Compression(ihv, b21_ref20);
	Compression_Modify(ihv, cv, scv, b22_ref20);	//compress a block, output chaining values cv and sufficient condition vector
	if(SetCheckAlgorithm(ihv, cv, scv, b22_ref20)){
		cout<<"ref 20 is OK, difference is m9 = -2^27, m2 = m12 = 2^31."<<endl;
	}
	//Reference 20, block difference is m9 = +2^27, m2 = m12 = 2^31
	ihv[0] = 0x67452301, ihv[1] = 0xefcdab89, ihv[2] = 0x98badcfe, ihv[3] = 0x10325476;	//iv 0
	uint32 b11_ref20[] = {0xce7e83ca, 0xcade345e, 0x381d83a5, 0x562edf19, 0xb93c9d41, 0xf9c4e244, 0x5b9b832f, 0xe16d2fe5, 
						  0x4b286759, 0x01fe0301, 0xa912ef12, 0x95a85769, 0x98adf66c, 0x8b1ad802, 0x291b44ab, 0x732af6a2};
	uint32 b12_ref20[] = {0x6a9b0d7d, 0x9aaeeda9, 0xe2255628, 0xb6a85040, 0xc7e08fd1, 0x077e530a, 0xdedd6809, 0xd20a7d80, 
						  0x55dfbe93, 0x70571c29, 0xc13d746c, 0x062792c8, 0xc5a152ce, 0x69727500, 0x351ec8f7, 0xcfffaf73};
	Compression(ihv, b11_ref20);
	Compression_Modify(ihv, cv, scv, b12_ref20);	//compress a block, output chaining values cv and sufficient condition vector
	if(SetCheckAlgorithm(ihv, cv, scv, b12_ref20)){
		cout<<"ref 20 is OK, difference is m9 = +2^27, m2 = m12 = 2^31."<<endl;
	}
	cout<<endl;
}
/* Get a random message block */
void GetRandomBlock(uint32 block[]){
	for(char i = 0; i < 16; i++){
		block[i] = rand();
		block[i] <<= 17;
		block[i] += rand();
	}
}