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

int main(int argc, char **argv)
{
	    /* On our trusted system we generate a new key
	     *      * (or read one in) and encrypt the secret data set.
	     *           */
/*parameter setting*/
	long m=0, p=2, r=1; // Native plaintext space
        // Computations will be 'modulo p'
	long L=50;          // Levels(number of ciphertext-primes that we want to support)
	long c=2;           // Columns in our key switching matrices
	long w=64;          // Hamming weight of secret key
	long d=1;           // field of extention ( #of calulations???? )
	long s=0;           // 
	long security = 80;
	int Lmax = 50;  //   # of multiplications
	ZZX G;
	double t = GetTime();
	m = FindM(security,L,c,p, d, 0, 0);
	
	cout << "Generating Key....." << endl; 
/*bulid a private key using prameter above*/
/*publick key was extracted from the private key*/
	FHEcontext context(m, p, r);
	// initialize context
	buildModChain(context, L);
	//avoid bootstrapping??
	//
	cout << "now generating key...." << endl;
	FHESecKey sk(context);
	sk.GenSecKey(w);
	const FHEPubKey& pk = sk;
	if(d == 0){
		G = context.alMod.getFactorsOverZZ()[0];
	}else{
		G = makeIrredPoly(p,d);
	}
	 // actually generate a secret key with Hamming weight w
	t = GetTime() - t;
	cout << "Key generation time; " << t << " seconds" << endl; 
	cout << "Generated key" << endl;
	cout << "(m,n=phi(m),p,r,L,c,w,d,s,k)=" << endl;
	cout << "(" << m << "," << context.zMStar.getPhiM() << ","<< p << "," <<
	r << "," << L << "," << c << "," << w <<
	"," << d << "," << s << "," << security
	<< ")" << endl;
	addSome1DMatrices(sk);//for relinearization
	EncryptedArray ea(context, G);
	long nslots = ea.size();
	cout << nslots << endl;	

//in practice 
	std::vector<long> v1;
	std::vector<long> v2;
/* should pack plain text into nslots*/
	for(int i = 1 ; i <= nslots; i++) {
		v1.push_back(i);
		v2.push_back(i+1);
	}
	Ctxt ctxt1(pk);
	Ctxt ctxt2(pk);
	ZZX V1,V2;
	ea.encode(V1,v1); ea.encode(V2,v2);
	//V1=??? V2=???

	t = GetTime();
	pk.Encrypt(ctxt1, V1);//encryption    vi--publickey-->ct1 ?
	pk.Encrypt(ctxt2, V2);//encryption    v2--puk-->ct2
	t = GetTime() - t;
	cout << "encryption time; " << t << " seconds" << endl; 
	cout << "now calculating...." << endl; 

	ZZX result;

	

	int times=1;
	//char Lstr[5];
	//sprintf(Lstr,"%ld",L);
	ostringstream oss;
	oss << L;
	string str1 = "/home/yu/graph/res/yu_vec_ml_L_";
	string mid = "_K_";
	str1+=oss.str()+mid;
	oss << security;
	string strT = ".txt";
	str1+=oss.str()+strT;
	ofstream myfile(str1.c_str());
	//ofstream myfile("/home/yu/graph/yu_ml_L_10.txt");
	
	for(times=1;times<=Lmax;times++){
		if(!(times==1)){
			myfile << ",";
		}
		myfile << times;
	}
	myfile<<endl;
	
	for(times=1;times<=Lmax;times++){
		if(!(times==1)){
			myfile << ",";
		}
		pk.Encrypt(ctxt1, V1);//encryption    vi--publickey-->ct1 ?
		t = GetTime();

		for(int j=1; j<=times ;j++){
			//ctxt1.multiplyBy2(ctxt2,ctxt3);
			ctxt1.multiplyBy(ctxt2);
			//ctxt1*=ctxt2;
			if( ctxt1.isCorrect() ){
				cout << j <<":	O" << endl; 
			}else{
				cout << j <<":	X" << endl; 
			}
		}//for end
			
		t = GetTime() - t;
		myfile << t; 
		cout << "finally," << endl; 
		if( ctxt1.isCorrect() ){
			cout <<"[" << times <<"] mult. can decrypt correctly :D OOOOO" << endl; 
			t = GetTime();
			sk.Decrypt(result,ctxt1);
			std::vector<long> decoded;
			t = GetTime() - t;
			cout << "Decryption time: " << t << " seconds" << endl;
		}else{
			cout << "XXXXX cannot decrypt correctly XXXXX" << endl; 
		}
		cout << "\n\n" << endl; 
	}
	myfile << endl;
	myfile.close();
	
/*  if this   flag is 1
 *  can  decrypt ciphertext  without  errors
 */ 

//	cout <<  plain << endl;
	//	myfile.close();
        return 0;
}
