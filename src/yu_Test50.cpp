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
#include <algorithm>
//#include <cybozu/option.hpp>

//cybozu::RandomGenerator rg;

//char *v;
using namespace std; 

inline int Dice()
{
	    return rand() % 192 + 1;

}

int L1=936,L0=234;

void TestIt(long m, long p, long r, long L, long c, long w, long d, long s, long K, int Lmax, bool isFindM=true){
	
	if (isFindM){
		m = FindM(K,L,c,p, d, s, 0);
	}
	cout << "Setting all params....." << endl; 
	double t = GetTime();
	FHEcontext context(m, p, r);
	buildModChain(context, L);
	t = GetTime() - t ;
	cout << "Setting time" << t << "seconds "<< endl; 
	ifstream vecfile("./vector50",std::ios::binary);
	string tmpstr;
	vecfile >> tmpstr;
	std::stringstream ss( tmpstr);
// for file writhing
	ostringstream oss1,oss2;
	oss1 << L;
	string str1 = "/home/yu/graph/res/CompareME";
	string mid = "_K_";
	string strT = ".txt";
	str1+=oss1.str()+mid;
	oss2 << K;
	str1+=oss2.str()+strT;
	ofstream myfile(str1.c_str());
	//ofstream myfile("/home/yu/graph/yu_ml_L_10.txt");
//for file wiritng processing
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
		is[i].resize(nslots);
		std::fill(is[i].begin(),is[i].end(),-1*i);
	}
	t=GetTime()-t;
	std::cerr << "L0 vectors nslots element push_back time "<< t << std::endl;


	std::cerr << "now packing L0 cipher-text " << std::endl;
	t=GetTime();
	for(int i=0;i<L0;i++){
		Ctxt ctxt(pk),ci(pk);// Enc(lookup_vec), Enc(crt_i)
		
		  double encotime=GetTime();
		  ea.encode(poly[i], tmpval[i]);
		  ea.encode(isX[i], is[i]);
		  encotime = GetTime() - encotime;
		  
		  double encrytime=GetTime();
		  pk.Encrypt(ctxt,poly[i]);
		  pk.Encrypt(ci,isX[i]);
		  encrytime = GetTime() - encrytime;
		  
		  double cpushtime=GetTime();
		  ctxts.push_back(ctxt);
		  cis.push_back(ci);
		  cpushtime=GetTime()-cpushtime;
		  if(i==0){
			std::cerr << "  encode 2 vector into 2 polynomials time " << encotime <<endl;
			std::cerr << "  encrypt 2 polynomials into 2 ctxts time is " << encrytime  <<endl;
			std::cerr << "  pushing 2 ciphert into 2 list time "<< cpushtime <<std::endl;
			std::cerr << "  total time "<< encotime+ encrytime+cpushtime << std::endl;
			std::cerr << "  this procedure is repeated  "<< L0 <<  "times" <<std::endl;
		  }
	}
	t=GetTime()-t;
	std::cerr << "L0 times 2 encode-encrypt-push_back time = " << t << std::endl;

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
double all=GetTime();

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
//rand for polynomials
//
/*
	for(int i=0;i<L0;i++){
		for(int k=0;k<nslots;k++){
			rands[i].push_back(Dice());
		}
	}
*/
	long ran=Dice();
	t= GetTime();
	//XXX random forjjjjjj
	std::vector<long> rands(nslots, ran);
	ZZX Ran;
	ea.encode(Ran,rands);
	long prev_r0=4;

	ZZX X1,X2;
for(int i=0;i<L0;i++){
	long x1 = -i-prev_r0;
	long x2=  x1+L0;
	ea.encode(iX,is[i]);
	std::vector<long> vecx1(nslots,x1);
	std::vector<long> vecx2(nslots,x2);
	ea.encode(X1,vecx1);
	ea.encode(X2,vecx2);
}


	all=GetTime();
for(int i=0;i<L0;i++){
	//pk.Encrypt(cqryp,qryxp);

	t = GetTime();
	  //ctxts[i].multiplyBy(cqry1);
	 // ZZX vec = poly[i]+Ran;
	  cqry1.multByConstant(Ran);
	  cqryp.addConstant(X1);
	  cqry1.multByConstant(Ran);
	  ctxts[i]+=cqryp; // ctxt+ctxt
	  //cqryp.multiplyBy(crn);
	 // ctxts[i].addCtxt(cqryp);
	t = GetTime() - t;
	if(i==0){
	std::cerr << "one time is " << t << std::endl; 
	}
	//std::cerr << "mul add mul:" << t << std::endl; 
	if(ContainsError){
//		cout << "error" << endl; 
		myfile << "0.0";
	}else{
		myfile << t;
	}

	if( ctxts[i].isCorrect() ){
//		cout <<"[" << times <<"] mult. can decrypt correctly :D OOOOO" << endl; 
//		t = GetTime();
		//sk.Decrypt(result,ctxt[i]);
	//	t = GetTime() - t;
	//	cout << "Decryption time: " << t << " seconds" << endl;
	}else{
		cout << "XXXXX cannot decrypt correctly XXXXX" << endl; 
	}

}
	all=GetTime()-all;
	std::cerr << "all calculation time" << all <<std::endl; 
	ContainsError=false;
	myfile << endl;
	myfile.close();


	//ZZX result;
	//sk.Decrypt(result,ct1);
	//ea.decode(tmpval[0],result);
	//std::cerr << tmpval[0] << std::endl;
}


int main(void)
{
	    /* On our trusted system we generate a new key
	     *      * (or read one in) and encrypt the secret data set.
	     *           */
/*parameter setting*/
	long m=0, p=2, r=20; // Native plaintext space
	//long m=0, p=2, r=59; // Native plaintext space
	//long m=0, p=2, r=59; // nofindM ver
        // Computations will be 'modulo p'
	long L=3;          // Levels(number of ciphertext-primes that we want to support)
	long c=2;           // Columns in our key switching matrices
	long w=64;          // Hamming weight of secret key
	long d=1;           // field of extention ( #of calulations???? )
	long s=L1;           // 
	long security = 128;
	int Lmax =(int)L;  //   # of multiplications

	Lmax=L;
	TestIt(m,p,r,L,c,w,d,s,security,Lmax);
	return 0;
}
