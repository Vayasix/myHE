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
	string str1 = "/home/yu/graph/res/psbyr";
	if(isFindM){
		str1 = "/home/yu/graph/res/psbyr";
		std::cerr << "including FindM" << std::endl; 
	}else{
		str1 = "/home/yu/graph/res/psbyr_noFindM";
		std::cerr << "without FindM" << std::endl; 
	}
	string midL = "_L_";
	string midK = "_K_";
	string strT = ".txt";
	oss1 << L;
	oss2 << K;
	str1+=midL+oss1.str();
	str1+=midK+oss2.str();
	str1+=strT;
	ofstream myfile(str1.c_str());

	std::vector<long> vecr;
	std::vector<double> contextTimes;
	std::vector<double> chainTimes;
	std::vector<double> keytimes;
	std::vector<double> evalkeytimes;

	for(int i=1;i<60;i++){
	//rifting r is replaced by i
		vecr.push_back(i);

		if (isFindM){
			m = FindM(K,L,c,p, d, s, 0);
		}

		cout << "Setting all params.....(m=" << m <<")"<< endl; 
		double t = GetTime();
		FHEcontext context(m, p, i);
		t = GetTime()-t;
		contextTimes.push_back(t);

		t = GetTime();
		buildModChain(context, L);
		t = GetTime() - t ;
		chainTimes.push_back(t);

		cout << "now generating key...." << endl;

		t = GetTime();
		FHESecKey sk(context);
		sk.GenSecKey(w);
		const FHEPubKey& pk = sk;
		t = GetTime() - t;
		keytimes.push_back(t);
	
		t = GetTime();
		addSome1DMatrices(sk);//for relinearization
		t = GetTime() - t;
		evalkeytimes.push_back(t);
	}

	for(int time=0; time<vecr.size(); time++){
		if(!(time==0)){
			myfile << ",";
		}
		myfile << vecr[time];
	}
	myfile<<endl;

	for(int time=0; time<contextTimes.size(); time++){
		if(!(time==0)){
			myfile << ",";
		}
		myfile << contextTimes[time];
	}
	myfile<<endl;

	for(int time=0; time<chainTimes.size(); time++){
		if(!(time==0)){
			myfile << ",";
		}
		myfile << chainTimes[time];
	}
	myfile<<endl;


	for(int time=0; time<keytimes.size(); time++){
		if(!(time==0)){
			myfile << ",";
		}
		myfile << keytimes[time];
	}
	myfile<<endl;

	for(int time=0; time<evalkeytimes.size(); time++){
		if(!(time==0)){
			myfile << ",";
		}
		myfile << evalkeytimes[time];
	}
	myfile<<endl;

	myfile.close();
}

int main(void)
{
	    /* On our trusted system we generate a new key
	     *      * (or read one in) and encrypt the secret data set.
	     *           */
/*parameter setting*/
	long m=0, p=2, r=1; // Native plaintext space
	//long m=0, p=2, r=59; // Native plaintext space
	//long m=0, p=2, r=59; // nofindM ver
        // Computations will be 'modulo p'
	long L=6;          // Levels(number of ciphertext-primes that we want to support)
	long c=2;           // Columns in our key switching matrices
	long w=64;          // Hamming weight of secret key
	long d=1;           // field of extention ( #of calulations???? )
	long s=0;           // 
	long security = 80;
	int Lmax =(int)L;  //   # of multiplications

	Lmax=L;
	TestIt(m,p,r,L,c,w,d,s,security,Lmax);
	TestIt(7781,p,r,L,c,w,d,s,security,Lmax,false);
	return 0;
}

