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

//define boolean function f(x, y, z)
#define F(x, y, z) (( (x) & (y) ) | ( (~x) & (z)))
//define boolean function g(x, y, z) 
#define G(x, y, z) (( (x) & (z) ) | ( (y) & (~z) ))
//define boolean function h(x, y, z) 
#define H(x, y, z) ( (x) ^ (y) ^ (z) )
//define boolean function i(x, y, z) 
#define I(x, y, z) ( (y) ^ ((x) | (~z)) )
//rotate shift operation
#define LRFunction(x, n) ( ( x << n ) | ( x >> ( 32 - n ) ) )
#define RRFunction(x, n) ( ( x >> n ) | ( x << ( 32 - n ) ) )
//step function
#define STEPFUNCTION(f, a, b, c, d, sr, rc, mw) (\
	a += f(b, c, d) + mw + rc,					 \
	a = b + LRFunction(a, sr)					)
//reverse step function
#define REVSTEPFUNCTION(f, a, b, c, d, sr, rc, mw)     (\
	a = RRFunction((a - b), sr) - mw - rc - f(b, c, d) )
//output the bits of cvi[5, 9, 14, 20, 31], bit selected order is 31, 5, 9, 14, 20
#define GetBits(scc1, scc2, scc3, scc4, scc5, cvi)   (\
	scc1 <<= 1, scc1 |=   cvi >> 31,					  \
	scc2 <<= 1, scc2 |= ((cvi >>  5) & 0x00000001),	  \
	scc3 <<= 1, scc3 |= ((cvi >>  9) & 0x00000001),	  \
	scc4 <<= 1, scc4 |= ((cvi >> 14) & 0x00000001),	  \
	scc5 <<= 1, scc5 |= ((cvi >> 20) & 0x00000001)	 )
typedef unsigned long int	uint32;
typedef long int			int32;
typedef unsigned short		uint16;
typedef short				int16;

//compression function of MD5, only used to check other algorithms
void Compression(uint32 ihv[], const uint32 block[]);
//modified compression function of MD5, input = ihv_k and block_k, 
//output = ihv_{k+1}, (cv37, cv38, cv39, cv40), sufficient condition vector(contain 5 values).
void Compression_Modify(uint32 ihv[], uint32 cv[], uint32 scv[], const uint32 block[]);
//reverse compression function,
//input are cv37, cv38, cv39, cv40 and message block,
//backward is to obtain ihv_k of the message block,
//forward is to get ihv_{k+1} of the message block.
void ReverseCompression(uint32 ihv[], const uint32 cv[], const uint32 block[]);
/* Distinguishable Set Check Algorithm */
bool DistinguishableSetCheckAlgorithm(const uint32 ihv[], const uint32 cv[], const uint32 scv[], const uint32 block[]);
/* Individual Checked Set Check Algorithm */
bool IndividualSetCheckAlgorithm(const uint32 ihv[], const uint32 cv[], const uint32 scv[], const uint32 block[]);
/* Non-Distinguishable Set Check Algorithm */
bool NonDistinguishableSetCheckAlgorithm(const uint32 ihv[], const uint32 cv[], const uint32 scv[], const uint32 block[]);
/* Correct Check Algorithm, all published differences are checked */
void CorrectCheckAlgorithm();
/* Get a random message block */
void GetRandomBlock(uint32 block[]);
