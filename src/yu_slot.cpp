#include "FHE.h"
#include "EncryptedArray.h"
#include <algorithm>
#include <NTL/lzz_pXFactoring.h>
#include <fstream>
#include <sstream>
#include <string>
#include <iostream>
#include <sys/time.h>
#include <sys/time.h>

class Params {
	public:
		long chosen_m; long p;
		long r; long L;
		long c; long w;
		long d; long s;
		long K; string file;
		vector<long> ss;
		vector<long> ms;
		vector<double> slots;
		vector<double> contextTs;
		vector<double> chainTs;
		vector<double> skGenTs;
		vector<double> keyMatrixTs;
		vector<double> EncodeTs;
		vector<double> EncryptTs;
		vector<double> AddTs;
		vector<double> MulTs;
		vector<double> DecryptTs;
		vector<double> DecodeTs;
	public:
		Params(long chosen_m, long p, long r, long L, long c, long w, long d, long s, long K);
		~Params();
		void setM(long m); void setP(long p);
		void setR(long r); void setL(long L);
		void setC(long c); void setW(long w);
		void setD(long d); void setS(long s);
		void setK(long K); void setF(string file);
		void CalcKeygen();
		void printParam();
};

void Params::setS(long s){
	Params::s=s;
}

void Params::printParam(){
		cout << "(m,p,r,L,c,w,d,s,k)=" << endl;
		cout << "(" << chosen_m << ","<< p << "," <<
		r << "," << L << "," << c << "," << w <<
		"," << d << "," << s << "," <<K
		<< ")" << endl;
}

Params::Params(long chosen_m, long p, long r, long L, long c, long w, long d, long s, long K)
{
	Params::chosen_m=chosen_m;
	Params::p=p;
	Params::r=r;
	Params::L=L;
	Params::c=c;
	Params::w=w;
	Params::d=d;
	Params::s=s;
	Params::K=K;
}

Params::~Params()
{ 
}

void Params::CalcKeygen(){
//FindMtime
//contextT
//chainT
//skGenT
//keyMatrixT
		cout << "Setting all params....." << endl;
		double t = GetTime();
		long m = FindM(K,L,c,p,d,s,chosen_m);
		double findMT = GetTime() - t;
		cout << "contexting....." << endl;
		t = GetTime();
		  FHEcontext context(m, p, r);
		double contextT = GetTime() - t;
		t = GetTime();
		  buildModChain(context, L);
		double chainT = GetTime() - t;
		t = GetTime();
		  FHESecKey sk(context);
		  sk.GenSecKey(w);
		double skGenT = GetTime() - t;
		t = GetTime();
		const FHEPubKey& pk = sk;
		 // actually generate a secret key with Hamming weight w
			addSome1DMatrices(sk);//for relinearization
//in practice 
		double keyMatrixT = GetTime() - t;

		ZZX G;
		if(d==0){
			G=context.alMod.getFactorsOverZZ()[0];
		}else{
			G=makeIrredPoly(p,d);
		}
		cout << "Generated key!  m=" << m << endl;
		EncryptedArray ea(context,G);
		long nslots=ea.size();
	
		if(std::find(slots.begin(), slots.end(), nslots) != slots.end()) {
			    context.zMStar.printout();
		} else {
			
			    ms.push_back(m);
			    slots.push_back(nslots);
			    ss.push_back(s);
			    contextTs.push_back(contextT);
			    chainTs.push_back(chainT);
			    skGenTs.push_back(skGenT);
			    keyMatrixTs.push_back(keyMatrixT);
			    vector<long> valvecs,tmpvec;
			    ZZX valX,tmpX;
			    Ctxt ctxt1(pk),ctmp(pk);
			    for(int j=0;j<nslots;j++){
				valvecs.push_back(1);
				tmpvec.push_back(j);
			    }
			    t = GetTime();
			    ea.encode(valX,valvecs);
			    t = GetTime()-t;
			    ea.encode(tmpX,tmpvec);
			    
			    EncodeTs.push_back(t);
			    t=GetTime();
			      pk.Encrypt(ctxt1,valX);
			    EncryptTs.push_back(GetTime()-t);
			      pk.Encrypt(ctmp,tmpX);//ignore since this is 2nd

			    t=GetTime();
			      ctxt1+=ctmp;
			    AddTs.push_back(GetTime()-t);
			    t=GetTime();
			      ctxt1.multiplyBy(ctmp);
			    MulTs.push_back(GetTime()-t);

			    t=GetTime();
			      sk.Decrypt(valX,ctxt1);
			    DecryptTs.push_back(GetTime()-t);
			    t=GetTime();
			      ea.decode(tmpvec,valX);
			    DecodeTs.push_back(GetTime()-t);
		}

}
/*
	long m=0, p=2, r=1;
	long L=10;
	long c=2;
	long w=64;
	long d=1;
	long s=0;
	long K = 128;
*/

int main(void)
{
/*parameter seting*/
	long m=0, p=2, r=20; // Native plaintext space
	long L=3;          // Levels(number of ciphertext-primes that we want to support)
	long c=2;           // Columns in our key switching matrices
	long w=64;          // Hamming weight of secret key
	long d=1;           // field of extention ( #of calulations???? )
	long s=0;           // 
	long K = 128;
	
	Params forS(m,p,r,L,c,w,d,s,K);

	for(int i=0;i<30000;i++){
		forS.setS(10*i);
		forS.printParam(); //DEBUG
		forS.CalcKeygen();
	}

	string file = "yu_byScomp";
	ofstream myfile( file.c_str() );

	for(int i=0;i<forS.ms.size();i++){
		myfile << forS.ms[i];
		if(i!=forS.ms.size()-1){
			myfile << ",";
		}
	}
	myfile << endl;

	for(int i=0;i<forS.ss.size();i++){
		myfile << forS.ss[i];
		if(i!=forS.ss.size()-1){
			myfile << ",";
		}
	}
	myfile << endl;

	for(int i=0;i<forS.slots.size();i++){
		myfile << forS.slots[i];
		if(i!=forS.slots.size()-1){
			myfile << ",";
		}
	}
	myfile << endl;

	for(int i=0;i<forS.contextTs.size();i++){
		myfile << forS.contextTs[i];
		if(i!=forS.contextTs.size()-1){
			myfile << ",";
		}
	}
	myfile << endl;

	for(int i=0;i<forS.chainTs.size();i++){
		myfile << forS.chainTs[i];
		if(i!=forS.chainTs.size()-1){
			myfile << ",";
		}
	}
	myfile << endl;


	for(int i=0;i<forS.skGenTs.size();i++){
		myfile << forS.skGenTs[i];
		if(i!=forS.skGenTs.size()-1){
			myfile << ",";
		}
	}
	myfile << endl;

	for(int i=0;i<forS.keyMatrixTs.size();i++){
		myfile << forS.keyMatrixTs[i];
		if(i!=forS.keyMatrixTs.size()-1){
			myfile << ",";
		}
	}
	myfile << endl;

	for(int i=0;i<forS.EncodeTs.size();i++){
		myfile << forS.EncodeTs[i];
		if(i!=forS.EncodeTs.size()-1){
			myfile << ",";
		}
	}
	myfile << endl;

	for(int i=0;i<forS.EncryptTs.size();i++){
		myfile << forS.EncryptTs[i];
		if(i!=forS.EncryptTs.size()-1){
			myfile << ",";
		}
	}
	myfile << endl;

	for(int i=0;i<forS.AddTs.size();i++){
		myfile << forS.AddTs[i];
		if(i!=forS.AddTs.size()-1){
			myfile << ",";
		}
	}
	myfile << endl;

	for(int i=0;i<forS.MulTs.size();i++){
		myfile << forS.MulTs[i];
		if(i!=forS.MulTs.size()-1){
			myfile << ",";
		}
	}
	myfile << endl;

	for(int i=0;i<forS.DecryptTs.size();i++){
		myfile << forS.DecryptTs[i];
		if(i!=forS.DecryptTs.size()-1){
			myfile << ",";
		}
	}
	myfile << endl;

	for(int i=0;i<forS.DecodeTs.size();i++){
		myfile << forS.DecodeTs[i];
		if(i!=forS.DecodeTs.size()-1){
			myfile << ",";
		}
	}
	myfile << endl;
	myfile.close();

	if(1)std::cerr << "END" << std::endl;
	return 0;
}
