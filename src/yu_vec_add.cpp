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
	long m=0, p=2, r=1; // Native plaintext space
        // Computations will be 'modulo p'
	long R=1;
	long L=10;          // Levels(number of ciphertext-primes that we want to support)
	long c=2;           // Columns in our key switching matrices
	long w=64;          // Hamming weight of secret key
	long d=1;           // circuit depth ( #of calulations???? )
	long s=0;           // circuit depth ( #of calulations???? )
	//The arguments p,d determine the plain text space F_{p^d}
	//
	//FindM(k, L, c, p, d, s, chosen_m, bool verbose=false)
	//
	//the argument s bounds from below the number of plaintext slots that we want to support
	//
	//chosen m: gives the ability to specify a particular m parameter and test if it satisfies all our constraints.
	//
	//
	long security = 80;
	ZZX G; // define the plaintext space
        /*  */
	if(L==0){
		L=3*R+3;
	}
	m = FindM(security,L,c,p, d, s, 0);
	cout << "(m,p,r,L,c,w,d,s,k)=" << endl;
	cout << "(" << m << "," << p << "," <<
	r << "," << L << "," << c << "," << w <<
	"," << d << "," << s << "," << security 
	<< ")" << endl; 
	//??????????????????//////
	//
/*bulid a private key using prameter above*/
/*publick key was extracted from the private key*/	
	FHEcontext context(m, p, r);
	// initialize context
	buildModChain(context, L, c);
	//modify the context, adding primes to the modulus chain
	FHESecKey sk(context);
	 // construct a secret key structure
	const FHEPubKey& pk = sk;
	// an "upcast": FHESecKey is a subclass of FHEPubrey
	if(d == 0){
		G = context.alMod.getFactorsOverZZ()[0];
	}else{
		G = makeIrredPoly(p,d);
	}
	sk.GenSecKey(w);
	 // actually generate a secret key with Hamming weight w
	cout << "Generated key" << endl;

	addSome1DMatrices(sk);
	// compute key-switching matrices that we need

/*????????*/
	EncryptedArray ea(context, G);
  	 // constuct an Encrypted array object ea that is
       // associated with the given context and the polynomial G
	long nslots = ea.size();
	cout << nslots << endl; 
/*For Encryption*/
ofstream myfile("/home/yu/graph/res/yu_vec.txt");
	std::vector<long> v1;
	std::vector<long> v2;
/* should pack plain text into nslots*/
	for(int i = 1 ; i <= nslots; i++) {
		v1.push_back(i);
		v2.push_back(i+1);
	}
	Ctxt ct1(pk);
	Ctxt ct2(pk);
	ZZX V1,V2;
	ea.encode(V1,v1); ea.encode(V2,v2);
	//V1=??? V2=???
	pk.Encrypt(ct1, V1);//encryption    vi--publickey-->ct1 ?
	pk.Encrypt(ct2, V2);//encryption    v2--puk-->ct2

/* some SIMD style computation*/

	 // On the public (untrusted) system we
	// can now perform our computation
	Ctxt ctSum = ct1;
	Ctxt ctPro = ct1;
	ZZX resSum,resMul;

int length=0;
int lmax=100000;
for(length=1;length<=lmax;length++){
	if(!(length==1 )){
	myfile << ",";
	}
myfile << length;
}

myfile<<endl;
double t;
for(length=1;length<=lmax;length++){
	if(!(length==1)){
		myfile << ",";
	}
	t = GetTime();
	for(int times=1; times<=length ;times++){
		ctSum += ct2;
	}
	t = GetTime() - t;
	myfile << t;
}
myfile << endl;
	sk.Decrypt(resSum,ctSum);
	//resSum=???
	std::vector<long> decoded;
	ea.decrypt(ctSum,sk,decoded);
	//cout << decoded  << endl;
/* Decryption the sum and product results*/
	vector<long> res;
	ea.decrypt(ctSum, sk, res);//decryption ctSum--->secretKey--->res??
	cout << "All computations are modulo " << p << "." << endl;

/*	
 *	for(int i = 0; i < res.size(); i ++) {
		        cout << v1[i] << " + " << v2[i] << " = " << res[i] << endl;
	}
	ea.decrypt(ctProd, secretKey, res);

	for(int i = 0; i < res.size(); i ++) {
	    cout << v2[i] << " * " << v2[i] << " = " << res[i] << endl;
	}
*/
        return 0;
}
