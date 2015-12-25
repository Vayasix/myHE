#include "FHE.h"
#include "replicate.h"
#include "EncryptedArray.h"
#include <NTL/lzz_pXFactoring.h>
#include <fstream>
#include <sstream>
#include <string>
#include <iostream>
#include <sys/time.h>

//char *v;
using namespace std; 

void TestIt(long m, long p, long r, long L, long c, long w, long d, long s, long K, int Lmax, bool isFindM=true){
	
	ostringstream oss1,oss2;
	string str1 = "/home/yu/graph/res/lowlevel_pack";
	if(isFindM){
		str1 = "/home/yu/graph/res/lowlevel_pack";
		std::cerr << "including FindM" << std::endl; 
	}else{
		str1 = "/home/yu/graph/res/lowlevel_pack_noFindM";
		std::cerr << "without FindM" << std::endl; 
	}
	string midK = "_K_";
	string strT = ".txt";
	oss2 << K;
	str1+=midK+oss2.str();
	str1+=strT;
	ofstream myfile(str1.c_str());

	std::vector<long> levels;
	std::vector<double> contextTimes;
	std::vector<double> chainTimes;
	std::vector<double> keytimes;
	std::vector<double> evalkeytimes;
	std::vector<double> calc1times;
	std::vector<double> calcAtimes;
	int L1=48,L0=192; 
	int Level=32;
//we change lebel jjj
	for(int i=30;i<Level;i++){
		L=i;
		myfile << i << ","<<endl;
		if (isFindM){
			m = FindM(K,L,c,p, d, s, 0);
		}

		cout << "Setting all params.....(m=" << m <<")"<< endl; 
		double t = GetTime();
		FHEcontext context(m, p, r);
		t = GetTime()-t;
		//contextTimes.push_back(t);

		t = GetTime();
		buildModChain(context, L);
		t = GetTime() - t ;
		//chainTimes.push_back(t);

		cout << "now generating key...." << endl;

		t = GetTime();
		FHESecKey sk(context);
		sk.GenSecKey(w);
		const FHEPubKey& pk = sk;
		t = GetTime() - t;
	//	keytimes.push_back(t);
	
		t = GetTime();
		addSome1DMatrices(sk);//for relinearization
		t = GetTime() - t;
	//	evalkeytimes.push_back(t);
		ZZX G;
		if(d==0){
			G=context.alMod.getFactorsOverZZ()[0];
		}else{
			G=makeIrredPoly(p,d);
		}
		cout << "Generated key" << endl;
		EncryptedArray ea(context,G);
		long nslots=ea.size();
		std::cerr << "slot numbers" << nslots <<std::endl; 
		Ctxt ct1(pk),ct2(pk);
		ZZX v1,v2;
		std::vector<long> vec1,vec2;
		for(int x=0;x<nslots;x++){
			vec1.push_back(1);
			vec2.push_back(0);
		}
		ea.encode(v1,vec1);
		ea.encode(v2,vec2);
		pk.Encrypt(ct1,v1);
		pk.Encrypt(ct2,v2);
		if(ct1.isCorrect()){
			std::cerr << "firstly ok :-))" << std::endl; 
		
		}
		
		double all=GetTime();
		for(int k=1;k<Level-2;k++){
			all=GetTime();
			ct1.multiplyBy(ct2);
			all=GetTime()-all;
			if(ct1.isCorrect()){
				std::cerr << "ooo" << std::endl; 
				myfile << all;
			}else{
				std::cerr << "XXX" << std::endl; 
				myfile << 0;
			}
			if(!(k==Level-3)){
				myfile << ",";
			}
		}
		myfile<<endl;
		std::cerr << "Level:"<< L << " calculation time" << all <<std::endl; 
	}
	myfile.close();
}

int main(void)
{
	    /* On our trusted system we generate a new key
	     *      * (or read one in) and encrypt the secret data set.
	     *           */
/*parameter setting*/
	long m=0, p=2, r=59; // Native plaintext space
	//long m=0, p=2, r=59; // Native plaintext space
	//long m=0, p=2, r=59; // nofindM ver
        // Computations will be 'modulo p'
	long L=6;          // Levels(number of ciphertext-primes that we want to support)
	long c=2;           // Columns in our key switching matrices
	long w=64;          // Hamming weight of secret key
	long d=1;           // field of extention ( #of calulations???? )
	long s=0;           // 
	long security = 128;
	int Lmax =(int)L;  //   # of multiplications

	Lmax=L;
	TestIt(m,p,r,L,c,w,d,s,security,Lmax);
//	TestIt(7781,p,r,L,c,w,d,s,security,Lmax,false);
	return 0;
}

