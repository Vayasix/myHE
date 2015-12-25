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
	long m=0, p=3, r=1; // Native plaintext space
	//m:
	//p:plaintext base
	//r:lifting
        // Computations will be 'modulo p'
	long L=16;          // Levels(number of ciphertext-primes that we want to support)
	long c=3;           // Columns in our key switching matrices
	long w=64;          // Hamming weight of secret key
	long d=1;           // circuit depth ( #of calulations???? )
	//The arguments p,d determine the plain text space F_{p^d}
	//
	//FindM(k, L, c, p, d, s, chosen_m, bool verbose=false)
	//
	//s: bounds from below the number of plaintext slots that we want to support
	// := minimum number of slots
	//chosen m: gives the ability to specify a particular m parameter and test if it satisfies all our constraints.
	//
	//
	long security = 192;
	ZZX G; // define the plaintext space
        /*  */
	m = FindM(security,L,c,p, d, 0, 0);
	cout << "m:  " << m << endl; 
	//??????????????????//////
	//
/*bulid a private key using prameter above*/
/*publick key was extracted from the private key*/	
	FHEcontext context(m, p, r);
	// initialize context
	buildModChain(context, L, c);
	//modify the context, adding primes to the modulus chain
	FHESecKey secretKey(context);
	 // construct a secret key structure
	const FHEPubKey& publicKey = secretKey;
	// an "upcast": FHESecKey is a subclass of FHEPubrey
	secretKey.GenSecKey(w);
	//hamming-weight w seckey
	cout << "Generated key" << endl;
	if(0 == d){
		G = context.alMod.getFactorsOverZZ()[0];
	}else{
		G = makeIrredPoly(p,d);
	}
	 // actually generate a secret key with Hamming weight w
	cerr << "G=  " << G << "\n";
	cerr << "generating key-switching matrices....";
	addSome1DMatrices(secretKey);
	// compute key-switching matrices that we need
	cerr << "done" << endl;
/*????????*/
	cerr << "computing masks and tables for rotation...";
	EncryptedArray ea(context, G);
	cerr << "done" << endl;
  	 // constuct an Encrypted array object ea that is
       // associated with the given context and the polynomial G
	long nslots = ea.size();
	PlaintextArray p0(ea);
	PlaintextArray p1(ea);
	PlaintextArray p2(ea);
	PlaintextArray p3(ea);
        // PlaintextArray objects associated with the given EncryptedArray ea
	p0.random();
	p1.random();
	p2.random();
	p3.random();
	// generate random plaintexts: slots initalized with random elements of Z[X]/(G,p^r)

	Ctxt c0(publicKey), c1(publicKey), c2(publicKey), c3(publicKey);
	// construct ciphertexts associated with the given public key


	ea.encrypt(c0, publicKey, p0);
	ea.encrypt(c1, publicKey, p1);
	ea.encrypt(c2, publicKey, p2);
	ea.encrypt(c3, publicKey, p3);
	// encrypt each PlaintextArray

	long shamt = RandomBnd(2*(nslots/2) + 1) - (nslots/2);
	     // shift-amount: random number in [-nslots/2..nslots/2]

	long rotamt = RandomBnd(2*nslots - 1) - (nslots - 1);
	     // rotation-amount: random number in [-(nslots-1)..nslots-1]
	PlaintextArray const1(ea);
	PlaintextArray const2(ea);
	const1.random();
	const2.random();
	// two random constants
// Perform some simple computations directly on the plaintext arrays:

	p1.mul(p0); // p1 = p1 * p0 (slot-wise modulo G)
	p0.add(const1); // p0 = p0 + const1
	p2.mul(const2); // p2 = p2 * const2
	PlaintextArray tmp_p(p1); // tmp = p1
	tmp_p.shift(shamt); // shift tmp_p by shamt
	p2.add(tmp_p); // p2 = p2 + tmp_p
	p2.rotate(rotamt); // rotate p2 by rotamt
	p1.negate(); // p1 = - p1
	p3.mul(p2); // p3 = p3 * p2
	p0.sub(p3); // p0 = p0 - p3

// Perform the same operations on the ciphertexts
	ZZX const1_poly, const2_poly;
	ea.encode(const1_poly, const1);
	ea.encode(const2_poly, const2);
	// encode const1 and const2 as plaintext polynomials
	double t = GetTime();
	c1.multiplyBy(c0); // c1 = c1 * c0
	c0.addConstant(const1_poly); // c0 = c0 + const1
	c2.multByConstant(const2_poly); // c2 = c2 * const2
	Ctxt tmp(c1); // tmp = c1
	ea.shift(tmp, shamt); // shift tmp by shamt
	c2 += tmp; // c2 = c2 + tmp
	ea.rotate(c2, rotamt); // rotate c2 by shamt
	c1.negate(); // c1 = - c1
	c3.multiplyBy(c2); // c3 = c3 * c2
	c0 -= c3; // c0 = c0 - c3
	t = GetTime() - t;
	cout << "calculation time is [" << t << "]  seconds" << endl; 
	// Decrypt the ciphertexts and compare
	PlaintextArray pp0(ea);
	PlaintextArray pp1(ea);
	PlaintextArray pp2(ea);
	PlaintextArray pp3(ea);
	ea.decrypt(c0, secretKey, pp0);
	ea.decrypt(c1, secretKey, pp1);
	ea.decrypt(c2, secretKey, pp2);
	ea.decrypt(c3, secretKey, pp3);
	if (!pp0.equals(p0)) cerr << "oops 0\n";
	if (!pp1.equals(p1)) cerr << "oops 1\n";
	if (!pp2.equals(p2)) cerr << "oops 2\n";
	if (!pp3.equals(p3)) cerr << "oops 3\n";

        return 0;
}
