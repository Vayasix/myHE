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
// for file writhing
	string str1 = "timebyslot";
	ofstream myfile(str1.c_str());
//for file wiritng processing
	for(int x=0;x<1000;x+=300){
		s+=x;
	if (isFindM){
		m = FindM(K,L,c,p, d, s, 0);
	}
	cout << "Setting all params....." << endl; 
	double t = GetTime();
	FHEcontext context(m, p, r);
	long n = context.zMStar.getPhiM();
	buildModChain(context, L);
	t = GetTime() - t ;
	cout << "Setting time" << t << "seconds "<< endl; 
	ifstream vecfile("./vector",std::ios::binary);
	string tmpstr;
	vecfile >> tmpstr;
	std::stringstream ss( tmpstr);
	int L1=192,L0=48;
	//std::vector< std::vector<long> > tmpval[192];// why vector ??? to encode polynomial
	std::vector<long> tmpval[L0];// why vector ??? to encode polynomial
//TODO
//acutually after getting pubkey on server 
//	 create L0 packed-ciphertexts(server vector)
//	TODO create f0/g0 replicated packed-ciphertext
//	TODO create each distinct random value packed-ciphert
//then compute 2 times for L1 and L0
//	TODO in this experiment one time calculation is enough
//	TODO 10回実験してそれぞれの計算時間とその平均値をだす

//FIXME
//  actually we get vector by real v0(v/L1?) and v1(v%L1)
//  should tmpval into L0 subvector after construction??
// 1. firstly not encrypted vector but just encode!!
// 2  secondly encrypted vector(so database is encrypted row by row)
	int vecid=-1,cnt=-1;
	std::string val;

	while(getline(ss,val,','))
	{
		cnt++;
		if(cnt%L1==0){
			vecid++;
		}
		//tmpval[vecid].push_back( atoi(val_) ) ;
		tmpval[vecid].push_back( atol(val.c_str()) );
	}
	vecfile.close();
		/*;
	for (int j=0;j<L0; j++){
		std::cerr << tmpval[j].size() << std::endl;
	}
	std::cerr << cnt << std::endl; 
	*/


//  FIXME END XXX 
	/* v=(int *)malloc(sizeof(int)*tmpval.size());
	for(int i=0;i<tmpval.size();i++){
		v[i]=tmpval[i];
	}
	*/

	cout << "now generating key...." << endl;
	t = GetTime();
	FHESecKey sk(context);
	sk.GenSecKey(w);
	const FHEPubKey& pk = sk;
	 // actually generate a secret key with Hamming weight w
	t = GetTime() - t;
	ZZX G;
	addSome1DMatrices(sk);//for relinearization
//in practice 
	if(d==0){
		G=context.alMod.getFactorsOverZZ()[0];
	}else{
		G=makeIrredPoly(p,d);
	}


	cout << "Generated key" << endl;
	EncryptedArray ea(context,G);
	long nslots=ea.size();
	cout << "(m,p,r,L,c,w,d,s,k)=" << endl;
	cout << "(" << m << ","<< p << "," <<
	r << "," << L << "," << c << "," << w <<
	"," << d << "," << s << "," <<K
	<< ")" << endl;
	cout << "n=phi(m) :"  << context.zMStar.getPhiM() << endl;
	cout << "PtxtSpace: :"  << context.zMStar.getP() << endl;
	cout << "nslots:" << nslots << endl;


//in practice 
/*TODO 
 * 1. lookup-vector into L0 subvectors
 *
 * pack into L1 slots and residence(slots-L1)  */


/* should pack plain text into nslots*/
	int crntVS=9216;

	if(L1 < nslots){
		for(int i=L1;i<nslots;i++){
			for(int j=0;j<L0;j++){
				tmpval[j].push_back((long)0);
			}
		}
	}

	std::cerr << tmpval[0] << std::endl;
	std::vector<Ctxt> ctxts;
	//std::vector<Ctxt> ccnts;
	ZZX poly[L0];
	//ZZX testvec;
	//ea.encode(testvec,tmpval[0]);
	//replicate(ea,ct1,1);

//look-up vector into ctxts 
	std::vector<long> is[L0];
	ZZX isX[L0];
	std::vector<Ctxt> cis;

	t=GetTime();
	for(int i=0;i<L0;i++){
		for(int j=0;j<nslots;j++){
			is[i].push_back(i);
		}
	}
	t=GetTime()-t;
	std::cerr << "packing time "<< t << std::endl;


	t=GetTime();
	for(int i=0;i<L0;i++){
		Ctxt ctxt(pk),ci(pk);// Enc(lookup_vec), Enc(crt_i)
		ea.encode(poly[i], tmpval[i]);
		ea.encode(isX[i], is[i]);
		pk.Encrypt(ctxt,poly[i]);
		pk.Encrypt(ci,isX[i]);
		ctxts.push_back(ctxt);
		cis.push_back(ci);
	}
	t=GetTime()-t;
	std::cerr << "pack and enco enc time " << t << std::endl;

	cout << "encryption time; " << t << " seconds" << endl; 
	cout << "now calculating...." << endl;
	int times=1;
	bool ContainsError=false;
	t = GetTime();


//XXX pseudo query
	std::vector<long> qry0,qry1,qryp,rn;
	ZZX qryx0,qryx1,qryxp,rnx;
	Ctxt cqry0(pk),cqry1(pk),cqryp(pk);
	Ctxt crn(pk);
	int f0=3,f1=10;
	for(int k=0;k<nslots;k++){
		rn.push_back(10);
		qryp.push_back(f0);
		if(k==f1){
			qry1.push_back(1);
			qry0.push_back(0);
			continue;
		}
		if(k==f0){
			qry0.push_back(1);
			qry1.push_back(0);
			continue;
		}
		qry0.push_back(0);
		qry1.push_back(0);
	}
	ea.encode(qryx0,qry0);
	ea.encode(qryx1,qry1);
	ea.encode(qryxp,qryp);
	ea.encode(rnx,rn);
	
	t = GetTime();
	pk.Encrypt(cqry0,qryx0);
	pk.Encrypt(cqry1,qryx1);
	pk.Encrypt(cqryp,qryxp);
	pk.Encrypt(crn,rnx);

	t = GetTime()-t;
	std::cerr <<  "encry " << t << std::endl;
//XXX psuedo Query
//
//
//XXX Recall that cqry0*v[i]+(cqryp-is)*rand          + rand2* auxilary
//calculation phaze 

	ZZX iX;


//XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX
//
//
// CALCULATION
//
//
//XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX
//omp_set_num_threads(2);
//omp_set_nested(1);
//#pragma omp parallel for
	myfile << L0 << "," << L1 <<"," << p << "," << r<< "," << m << "," << n << "," << s << "," <<nslots << ",";
	double all=GetTime();

for(int i=0;i<L0;i++){
	//t = GetTime();
	pk.Encrypt(cqryp,qryxp);
	ea.encode(iX,is[i]);
	t = GetTime();
	  ctxts[i].multiplyBy(cqry1);
	  //ctxts[i]*=(cqry1);
	  cqryp.addConstant(iX);
	  cqryp.multiplyBy(crn);
	  //cqryp*=(crn);
	  ctxts[i].addCtxt(cqryp);
	t = GetTime() - t;
	if(i==0) {
		if(ContainsError){
			myfile << "0.0,";
		}else{
			myfile << t << ",";
		}
	}
	std::cerr << "mul add mul:" << t << std::endl; 

	if( ctxts[i].isCorrect() ){

	}else{
		cout << "XXXXX cannot decrypt correctly XXXXX" << endl; 
	}
}
	all=GetTime()-all;
	myfile << all << endl;
	std::cerr << "all calculation time" << all <<std::endl;
	}
	myfile.close();
}


int main(void)
{
	    /* On our trusted system we generate a new key
	     *      * (or read one in) and encrypt the secret data set.
	     *           */
/*parameter setting*/
	long m=0, p=2, r=10; // Native plaintext space
	//long m=0, p=2, r=59; // Native plaintext space
	//long m=0, p=2, r=59; // nofindM ver
        // Computations will be 'modulo p'
	long L=5;          // Levels(number of ciphertext-primes that we want to support)
	long c=2;           // Columns in our key switching matrices
	long w=64;          // Hamming weight of secret key
	long d=1;           // field of extention ( #of calulations???? )
	long s=192;           // 
	long security = 128;
	int Lmax =(int)L;  //   # of multiplications

	Lmax=L;
	TestIt(m,p,r,L,c,w,d,s,security,Lmax);
	return 0;
}

