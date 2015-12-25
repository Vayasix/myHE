#include "FHE.h"
#include "EncryptedArray.h"
#include <NTL/lzz_pXFactoring.h>
#include <fstream>
#include <sstream>
#include <sys/time.h>
#include "OldEvalMap.h"
#include "hypercube.h"
#include "powerful.h"

int main(int argc, char **argv)
{
	    /* On our trusted system we generate a new key
	     *      * (or read one in) and encrypt the secret data set.
	     *           */
/*parameter setting*/
	long m=119, p=2, r=20; // Native plaintext space
        // Computations will be 'modulo p'
	long L=3;          // Levels(number of ciphertext-primes that we want to support)
	long c=2;           // Columns in our key switching matrices
	long w=64;          // Hamming weight of secret key
	long d=1;           // circuit depth ( #of calulations???? )
	long s=50;
	FHEcontext* aaa;
	Ctxt *ab1,*ab2;
	FHEPubKey *pubpub;
	EncryptedArray* ea2;
	//The arguments p,d determine the plain text space F_{p^d}
	//
	//FindM(k, L, c, p, d, s, chosen_m, bool verbose=false)
	//
	//the argument s bounds from below the number of plaintext slots that we want to support
	//
	//chosen m: gives the ability to specify a particular m parameter and test if it satisfies all our constraints.
	//
	//
	long security = 40;
	ZZX G; // define the plaintext space
        /*  */

	//m = FindM(security,L,c,p, d, s, 0);
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
	EncryptedArray ea(context, G);
	long nslots = ea.size();
	cout << nslots << endl; 
/*For Encryption*/
	std::vector<long> v1(nslots,5);
	std::vector<long> v2(nslots,0);
	std::vector<long> vv(nslots,3);
	std::vector<ZZX> vZ;
	v1[2]=3;

	//5 5 3 5 5 5 5 5 5 5 5.....
	std::cerr << v1 << std::endl; 
	ZZX V1,V2,V3; ZZ ax(1),bx(3);
	ZZ_p::init(bx);
	ZZ_pX f;
	ea.encode(V1,v1);
	ea.encode(V2,v2);
	ea.encode(V3,vv);
	Ctxt cv2(pk);
	pk.Encrypt(cv2,V2);
	NewPlaintextArray pa1(ea);
	std::cerr << "First V1 is " << std::endl; 
	std::cerr << V1 << std::endl; 
	
	f=to_ZZ_pX(V1);
	std::cerr << "mod V1 of f is " << std::endl; 
	std::cerr << f << std::endl; 
	
	conv(V1,f);
	cv2.addConstant(V1);
	ea.decode(v2,V1);
	std::cerr << v2 << std::endl; 
	sk.Decrypt(V1,cv2);
	ea.decode(v2,V1);
	std::cerr << v2 << std::endl; 

        return 0;
}
