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
#include <time.h>  
#include <iostream>
using namespace std;

#define TESTTIMES 0x1000000

int main(){
	//Correct Check Algorithm, all published differences are checked
	CorrectCheckAlgorithm();
	cout<<"Total number of test is: "<<TESTTIMES<<endl<<endl;
	srand((unsigned int)time(NULL));
	bool isFindACollisionBlock = false;
	uint32 i = 0;
	uint32 block[16], cv[4], scv[5];
	uint32 ihv[4] = {0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476};
	//random message time consuming
	double start = clock();
	for(i = 0; i < TESTTIMES; i++){
		GetRandomBlock(block);
	}
	double end = clock(); 
	double intval_randomMsg = end - start;
	cout<<"Generate random message takes "<<intval_randomMsg<<" milliseconds."<<endl<<endl;
	
	//MD5 hash function time consuming
	start = clock();
	for(i = 0; i < TESTTIMES; i++){
		GetRandomBlock(block);
		Compression(ihv, block);
	}
	end = clock(); 
	double intval_randomTest = end - start;
	cout<<"Standard MD5 hash takes "<<intval_randomTest<<" milliseconds."<<endl;

	cout<<endl<<"Collision Detection Algorithm start!"<<endl;
	start = clock();
	//Collision Detection, a 32-bit array is used to represent the 512-bit random message block
	for(i = 0; i < TESTTIMES; i++){
		GetRandomBlock(block);
		//compress a block, output chaining values cv and sufficient condition vector
		Compression_Modify(ihv, cv, scv, block);	//bit selected order is 31, 5, 9, 14, 20
		if(DistinguishableSetCheckAlgorithm(ihv, cv, scv, block)){	//check Distinguishable Set
			cout<<"the "<<i<<"-th block is a collision block in Distinguishable Set."<<endl;
			isFindACollisionBlock = true;
		}
		if(IndividualSetCheckAlgorithm(ihv, cv, scv, block)){		//check Individual Checked Set
			cout<<"the "<<i<<"-th block is a collision block in Individual Checked Set."<<endl;
			isFindACollisionBlock = true;
		}
		if(NonDistinguishableSetCheckAlgorithm(ihv, cv, scv, block)){	//check Non-Distinguishable Set
			cout<<"the "<<i<<"-th block is a collision block in Non-Distinguishable Set."<<endl;
			isFindACollisionBlock = true;
		}
	}
	if(!isFindACollisionBlock){
		cout<<"there is no collision block in current message."<<endl;
	}
	//time finished
	end = clock(); 
	double intval_randomCollisionTest = end - start;
	//output time 
	cout<<"Collision Detection takes "<<intval_randomCollisionTest<<" milliseconds."<<endl<<endl;
	//output Hashing times per 1 random block
	cout<<"For random message block, averger check number is: "
		<<((intval_randomCollisionTest - intval_randomMsg) / (intval_randomTest - intval_randomMsg))
		<<endl;
	getchar();
	return 0;
}
