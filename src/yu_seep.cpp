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
	cout << "now generating key...." << endl;
	if(d == 0){
		G = context.alMod.getFactorsOverZZ()[0];
	}else{
		G = makeIrredPoly(p,d);
	}
	 // actually generate a secret key with Hamming weight w
	cout << "(m,n=phi(m),p,r,L,c,w,d,s,k)=" << endl;
	cout << "(" << m << "," << context.zMStar.getPhiM() << ","<< context.zMStar.getOrdP()<< ","<< p << "," <<
	r << "," << L << "," << c << "," << w <<
	"," << d << "," << s << "," << security
	<< ")" << endl;
	EncryptedArray ea(context, G);
	long nslots = ea.size();
	cout << nslots << endl;	
        return 0;
}
