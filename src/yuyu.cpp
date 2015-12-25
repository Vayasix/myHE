#include "FHE.h"
#include "replicate.h"
#include "EncryptedArray.h"
#include <NTL/lzz_pXFactoring.h>
#include <fstream>
#include <sstream>
#include <string>
#include <iostream>
#include <sys/time.h>
//#include <thread>
#include <omp.h>
//#include <cybozu/option.hpp>

//cybozu::RandomGenerator rg;

//char *v;
using namespace std; 


void TestIt(long m, long p, long r, long L, long c, long w, long d, long s, long K, int Lmax, bool isFindM=true){
	if (isFindM){
		m = FindM(K,L,c,p, d, s, 0);
	}
	cout << "Setting all params....." << endl; 
	FHEcontext context(m, p, r);
	buildModChain(context, L);
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

	EncryptedArray ea(context,G);
	vector<long> vec,vecr;
	ZZX X,Y;
	Ctxt ct1(pk),ct2(pk);
		for(int j=0;j<ea.size();j++){
			vec.push_back(-2);
			vecr.push_back(1);
		}
	ea.encode(X, vec);
	ea.encode(Y, vecr);
	
	std::cerr << X << std::endl; 
	std::cerr << Y << std::endl; 
	std::cerr << X+Y << std::endl; 
	ea.decode(vecr,X+Y);
	std::cerr << vecr << std::endl; 
}


int main(void)
{
	    /* On our trusted system we generate a new key
	     *      * (or read one in) and encrypt the secret data set.
	     *           */
/*parameter setting*/
	long m=0, p=101, r=1; // Native plaintext space
	//long m=0, p=2, r=59; // Native plaintext space
	//long m=0, p=2, r=59; // nofindM ver
        // Computations will be 'modulo p'
	long L=3;          // Levels(number of ciphertext-primes that we want to support)
	long c=2;           // Columns in our key switching matrices
	long w=64;          // Hamming weight of secret key
	long d=1;           // field of extention ( #of calulations???? )
	long s=100;           // 
	long security = 128;
	int Lmax =(int)L;  //   # of multiplications

	Lmax=L;
	TestIt(m,p,r,L,c,w,d,s,security,Lmax);
	return 0;
}

