#include "FHE.h"
#include "EncryptedArray.h"
#include <NTL/lzz_pXFactoring.h>
#include <fstream>
#include <sstream>
#include <sys/time.h>


int main(int argc, char **argv)
{
	    /* On our trusted system we generate a new key
	     *      * (or read one in) and encrypt the secret data set.
	     *           */
/*parameter setting*/
	long chosen_m=0, p=2, r=1; // Native plaintext space
        // Computations will be 'modulo p'
	long L=0;          // Levels(number of ciphertext-primes that we want to support)
	long c=2;          // Columns in our key switching matrices
	long w=64;         // Hamming weight of secret key
	long d=1;          //
	long s=0;          // 
	long security = 80;
	double t = GetTime();
	long m = FindM(security,L,c,p, d, 0, chosen_m);
	cout << "(m,p,r,L,c,w,d,s,k)=" << endl;
	cout << "(" << m << "," << p << "," <<
	r << "," << L << "," << c << "," << w <<
	"," << d << "," << s << "," << security
	<< ")" << endl;
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
	 // actually generate a secret key with Hamming weight w
	t = GetTime() - t;
	cout << "Key generation time; " << t << " seconds" << endl; 
	cout << "Generated key" << endl;

	addSome1DMatrices(sk);//for relinearization
//in practice 
	Ctxt ctxt1(pk);
	Ctxt ctxt2(pk);
	ZZX plain = to_ZZX(0);
	ZZX plain2 = to_ZZX(0);

	cout << plain << endl; 
	cout << plain2 << endl; 

	t = GetTime();
	pk.Encrypt(ctxt1, plain);//encryption    vi--publickey-->ct1 ?
	pk.Encrypt(ctxt2, plain2);//encryption    vi--publickey-->ct1 ?
	t = GetTime() - t;
	cout << "encryption time; " << t << " seconds" << endl; 
	cout << "now calculating...." << endl; 

	ofstream myfile("/home/yu/graph/res/yu_add.txt");
	int length=0;
	int lMAX = 100000;
	for(length=1;length<=lMAX;length++){
		if(!(length==1)){
			myfile << ",";
		}
		myfile << length;
	}
	myfile<<endl;
	for(length=1;length<=lMAX;length++){
		if(!(length==1)){
			myfile << ",";
		}
		t = GetTime();
		for(int times=1;times<=length;times++){
			ctxt1.addCtxt(ctxt2);
		}
		t = GetTime() - t;
		myfile << t; 
//	cout << "XXXXXXXXX  addition time :  " << t << " seconds" << endl;
	}
	myfile<<endl;
	myfile.close();
/*	t = GetTime();
	ctxt1.multByConstant(to_ZZX(2));// ENC(20)
	t = GetTime() - t;
	cout << "constant muliplication time; " << t << " seconds" << endl; 
*/

//	t = GetTime();
//	ctxt1.addConstant(to_ZZX(10));// ENC(30)
//	t = GetTime() - t;
//	cout << "constant addition time; " << t << " seconds" << endl; 
//using reLineration
//
//	t = GetTime();
//	ctxt1.multiplyBy(ctxt1);//
//	t = GetTime() - t;
//	cout << "Mult time between Cipher: " << t << " seconds" << endl; 

//	not using reLineration
//	ofstream myfile("/home/yu/graph/yu_result.txt");

//	t = GetTime();
//	ctxt1.multiplyBy(ctxt1);// ENC(30)*ENC(30)
//	ctxt1 *= ctxt1;// ENC(900)*ENC(900)
//	cout << "reni" << t << " seconds" << endl; 

//	Ctxt ct(pk);
//	Ctxt ct2(pk);
//	ZZX pl = to_ZZX(1);
//	ZZX pl2 = to_ZZX(1);
//	pk.Encrypt(ct, pl);//encryption    vi--publickey-->ct1 ?
//	pk.Encrypt(ct2, pl2);//encryption    vi--publickey-->ct1 ?

//	ct2*=ct2;//
//	t = GetTime() - t;
//	cout << "rerererr: " << t << " seconds" << endl; 
//	t = GetTime() - t;
//	cout << "Mult time between Cipher: not renirelization" << t << " seconds" << endl; 
	t = GetTime();
	sk.Decrypt(plain,ctxt1);
	t = GetTime() - t;
	cout << "Decryption time: " << t << " seconds" << endl;
	//	myfile << t << endl;
	cout <<  ctxt1.isCorrect() << endl;
	//	myfile.close();
//	system("python /home/yu/graph/graph.py");
        return 0;
}
