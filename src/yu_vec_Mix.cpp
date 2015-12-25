/*        multiplyBy   with KeySwitching--ノイズを減らす
 *        *=  without  KeySwitching  ノイズを減らさない
 */
#include "FHE.h"
#include "EncryptedArray.h"
#include <NTL/lzz_pXFactoring.h>
#include <fstream>
#include <sstream>
#include <string>
#include <iostream>
#include <sys/time.h>


void TestIt(long m, long p, long r, long L, long c, long w, long d, long s, long K, int Lmax){
	m = FindM(K,L,c,p, d, 0, 0);
	cout << "Setting all params....." << endl; 
	FHEcontext context(m, p, r);
	buildModChain(context, L);

	cout << "now generating key...." << endl;
	double t = GetTime();
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
	std::vector<long> v1;
	std::vector<long> v2;
	std::vector<long> v3;
	std::vector<long> v4;

/* should pack plain text into nslots*/
	for(int i = 1 ; i <= nslots; i++) {
		v1.push_back(1);
		v2.push_back(2);
		v3.push_back(3);
		v4.push_back(4);
	}

	Ctxt ctxt1(pk);
	Ctxt ctxt2(pk);
	Ctxt ctxt3(pk);
	Ctxt ctxt4(pk);
	ZZX V1,V2,V3,V4;
	ea.encode(V1,v1); ea.encode(V2,v2);
	ea.encode(V3,v3); ea.encode(V4,v4);


	t = GetTime();
	pk.Encrypt(ctxt1, V1);//encryption    vi--publickey-->ct1 ?
	pk.Encrypt(ctxt2, V2);//encryption    vi--publickey-->ct1 ?
	pk.Encrypt(ctxt3, V3);//encryption    vi--publickey-->ct1 ?
	pk.Encrypt(ctxt4, V4);//encryption    vi--publickey-->ct1 ?
	t = GetTime() - t;

	cout << "encryption time; " << t << " seconds" << endl; 
	cout << "now calculating...." << endl;
	int times=1;

	ostringstream oss1,oss2;
	oss1 << L;
	string str1 = "/home/yu/graph/res/yu_vec_Mix_L_";
	string mid = "_K_";
	string strT = ".txt";
	str1+=oss1.str()+mid;
	oss2 << K;
	str1+=oss2.str()+strT;
	ofstream myfile(str1.c_str());
	//ofstream myfile("/home/yu/graph/yu_ml_L_10.txt");
	
	for(times=1;times<=Lmax;times++){
		if(!(times==1)){
			myfile << ",";
		}
		myfile << times;
	}
	myfile<<endl;
	ZZX result;	
	bool ContainsError=false;
	for(times=1;times<=Lmax;times++){
		if(!(times==1)){
			myfile << ",";
		}
		pk.Encrypt(ctxt1, V1);//encryption    vi--publickey-->ct1 ?
		pk.Encrypt(ctxt3, V3);//encryption    vi--publickey-->ct1 ?

		t = GetTime();

		for(int j=1; j<=times ;j++){
			ctxt1.multiplyBy(ctxt2);
			ctxt3.multiplyBy(ctxt4);
			//ctxt1*=ctxt2;
			//ctxt3*=ctxt4;
			ctxt1.addCtxt(ctxt3);

			//ctxt1.multiplyBy(ctxt3);
			//ctxt1.multiplyBy2(ctxt1,ctxt3);
			if( ctxt1.isCorrect() ){
				ContainsError=false;	
				cout << j <<":	O" << endl; 
			}else{
				ContainsError=true;
				cout << j <<":	X" << endl; 
			}
		}//for end
			
		t = GetTime() - t;
		if(ContainsError){
			cout << "error" << endl; 
			myfile << "0.0";
		}else{
			myfile << t;
		}
		cout << "finally," << endl; 
		if( ctxt1.isCorrect() ){
			cout <<"[" << times <<"] mult. can decrypt correctly :D OOOOO" << endl; 
			t = GetTime();
			sk.Decrypt(result,ctxt1);
			t = GetTime() - t;
			cout << "Decryption time: " << t << " seconds" << endl;
		}else{
			cout << "XXXXX cannot decrypt correctly XXXXX" << endl; 
		}
		cout << "\n\n" << endl; 
		ContainsError=false;
	}
	myfile << endl;
	myfile.close();
}

int main(int argc, char **argv)
{
	    /* On our trusted system we generate a new key
	     *      * (or read one in) and encrypt the secret data set.
	     *           */
/*parameter setting*/
	long m=0, p=2, r=1; // Native plaintext space
        // Computations will be 'modulo p'
	long L=20;          // Levels(number of ciphertext-primes that we want to support)
	long c=2;           // Columns in our key switching matrices
	long w=64;          // Hamming weight of secret key
	long d=1;           // field of extention ( #of calulations???? )
	long s=0;           // 
	long security = 80;
	int Lmax =(int)L;  //   # of multiplications

	L=atoi(argv[1]);
	security=atoi(argv[2]);
	Lmax=L;
	TestIt(m,p,r,L,c,w,d,s,security,Lmax);
	return 0;
}

