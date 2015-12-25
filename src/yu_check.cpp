#include "FHE.h"
#include "EncryptedArray.h"
#include <NTL/lzz_pXFactoring.h>
#include <fstream>
#include <sstream>
#include <string>
#include <iostream>
#include <sys/time.h>


void TestIt(long m, long p, long r, long L, long c, long w, long d, long s, long K, int Lmax){
	cout << "Setting all params....." << endl; 
	double t=GetTime();
	m = FindM(K,L,c,p, d, 0, m);
	FHEcontext context(m, p, r);
	buildModChain(context, L);

	cout << "now generating key...." << endl;
	t = GetTime();
	FHESecKey sk(context);
	sk.GenSecKey(w);
	const FHEPubKey& pk = sk;
	 // actually generate a secret key with Hamming weight w
	ZZX G;
	addSome1DMatrices(sk);//for relinearization
//in practice 
	if(d==0){
		G=context.alMod.getFactorsOverZZ()[0];
	}else{
		G=makeIrredPoly(p,d);
	}
	cout << "Generated key" << endl;
	double KeyGenT = GetTime() - t;

	ostringstream oss1,oss2;
	oss1 << L;
	string str1 = "/home/yu/graph/res/yu_FINDM_L_";
	string mid = "_K_";↲
	string mid = "_M_";↲
	string strT = ".txt";↲
	str1+=oss1.str()+mid;↲
	oss2 << K;↲
	str1+=oss2.str()+strT;↲
	ofstream myfile(str1.c_str());↲
	myfile << ",";↲
	}


//int main(int argc, char **argv)

int main(void){
/*parameter seting*/
	long m=10261, p=2, r=1; // Native plaintext space
        // Computations will be 'modulo p'
	long L=10;          // Levels(number of ciphertext-primes that we want to support)
	long c=2;           // Columns in our key switching matrices
	long w=64;          // Hamming weight of secret key
	long d=1;           // field of extention ( #of calulations???? )
	long s=0;         // 
	long security = 128;
	int Lmax =(int)L;  //   # of multiplications

//	L=atoi(argv[1]);
//	security=atoi(argv[2]);
//	m=atoi(argv[3]);
       for(int i=0;i<30;i++){
	L=i+4;
	Lmax=L-3;
	double t=GetTime();
	TestIt(m,p,r,L,c,w,d,s,security,Lmax);
	t=GetTime()-t;
	std::cerr <<"level " << L << "    " <<t << " seconds " << std::endl; 
       }
	return 0;
}

