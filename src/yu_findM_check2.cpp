#include "FHE.h"
#include "EncryptedArray.h"
#include <NTL/lzz_pXFactoring.h>
#include <fstream>
#include <sstream>
#include <string>
#include <iostream>
#include <sys/time.h>


void TestIt(long m, long p, long r, long L, long c, long w, long d, long s, long K, string file, long mmax){

	ofstream myfile( file.c_str(), ios::app );
	vector<long> ms;

	for(int i=0;i<mmax;i++){ 
	//	cout << "Setting all params....." << endl;

		double t = GetTime();
		m = FindM(K,L,c,p,d,s,i+10000);
		FHEcontext context(m, p, r);
		buildModChain(context, L);
		cout << "now generating key...." << endl;
		FHESecKey sk(context);
		sk.GenSecKey(w);
		const FHEPubKey& pk = sk;
		 // actually generate a secret key with Hamming weight w
		addSome1DMatrices(sk);//for relinearization
//in pra	ctice 
		t = GetTime() - t;

//		ZZX G;
//		if(d==0){
//			G=context.alMod.getFactorsOverZZ()[0];
//		}else{
//			G=makeIrredPoly(p,d);
//		}
	//	cout << "Generated key!  m=" << m << endl;
//		EncryptedArray ea(context,G);
//		long nslots=ea.size();
//		cout << "(m,p,r,L,c,w,d,s,k)=" << endl;
//		cout << "(" << m << ","<< p << "," <<
//		r << "," << L << "," << c << "," << w <<
//		"," << d << "," << s << "," <<K
//		<< ")" << endl;
		//context.zMStar.printout();
//		cout << "  \ell=nslots:" << nslots << endl;

		myfile << t;
		ms.push_back(m);
		std::cerr << " time : "<< t << std::endl; 
		if(i==mmax-1){
			myfile<<endl;
			break;
		}
		myfile << ",";
	}

	for(int j=0; j<ms.size();j++){
		myfile << ms[j];
		if( j==ms.size()-1 ){
			myfile << endl;
			break;
		}
		myfile << ",";
	}
	myfile.close();
}

int main(void)
{
/*parameter seting*/
	long m=0, p=2, r=1; // Native plaintext space
        // Computations will be 'modulo p'
	long L=10;          // Levels(number of ciphertext-primes that we want to support)
	long c=2;           // Columns in our key switching matrices
	long w=64;          // Hamming weight of secret key
	long d=1;           // field of extention ( #of calulations???? )
	long s=0;           // 
	long K = 128;
	long mmax = 20000;
	string file = "/home/yu/graph/res/FindM2_L";

	ostringstream oss1,oss2;
	oss1 << L;
	string mid = "_K_";
	string strT = ".txt";
	file+=oss1.str()+mid;
	oss2 << K;
	file+=oss2.str()+strT;
	ofstream myfile( file.c_str() );
	for(int i=0;i<mmax;i++){
		myfile << i;
		if(i==mmax-1){
			break;
		}
		myfile << ",";
	}
	myfile << endl;
	myfile.close();

	TestIt(m,p,r,L,c,w,d,s,K,file,mmax);
	
	return 0;
}
