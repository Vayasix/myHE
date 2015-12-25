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
	long m=0, p=2, r=20; // Native plaintext space
        // Computations will be 'modulo p'
	long L=3;          // Levels(number of ciphertext-primes that we want to support)
	long c=2;           // Columns in our key switching matrices
	long w=64;          // Hamming weight of secret key
	long d=1;           // circuit depth ( #of calulations???? )
	long s=10;
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
	long security = 28;
	ZZX G; // define the plaintext space
        /*  */

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
	std::vector<long> v1(nslots,1);
	std::vector<long> v2(nslots,0);
	std::vector<long> vr(nslots,3);
	v1[2]=3;v2[3]=5;
	//v1 = 1 1 3 1 1 1 1 1 1 1 1 1 1 1 1 
	//v2 = 0 0 0 5 0 0 0 0 0 0 0 0 0 0 0
	std::vector<long> rvec;
/* should pack plain text into nslots*/
	Ctxt ct1(pk);
	//v1 = 1 1 3 1 1 1 1 1 1 1 1 1 1 1 1 
	Ctxt ct2(pk);
	Ctxt ctr(pk);
	//ZZ px;
	//px =11;
	//ZZ_p::init(px);
	//
	ZZX AX;
	ZZX V1,V2,res;
	ea.encode(V2,v2);
	pk.Encrypt(ct2, V2);//encryption    v2--puk-->ct2
	ea.encode(AX,v1);
	ct2.addConstant(AX);
	sk.Decrypt(AX,ct2);
	ea.decode(v1,AX);
	std::cerr << v1 << std::endl; 

	
	//
	ZZX randX;
	//ZZX randX(9);
	ZZ ax(1);

	ea.encode(V1,v1); ea.encode(V2,v2);
	ea.encode(randX,vr);
	//V1=??? V2=???
	//ZZ_pX modV1;
	//ZZ_pX modV1= to_ZZ_pX(V1+9);
	//conv(modV1, V1);
	//conv(V1, modV1);
	V1=V1%randX;
	pk.Encrypt(ct1, V1);//encryption    vi--publickey-->ct1 ?
	//1111111111111111111111
	//std::cerr << "Polynomial V1 is" << std::endl; 
	//std::cerr << V1 << std::endl; 
	pk.Encrypt(ct2, V2);//encryption    v2--puk-->ct2
	//000000000000000000000000
	std::ofstream sks("seckeys",std::ios::binary);
	sks << sk <<endl;
	sks.close();

	std::ofstream pubs("publickeys",std::ios::binary);
	pubs << pk <<endl;
	pubs.close();

	std::cerr << "calculation start" << std::endl; 

	ct1.addConstant(ax);
	sk.Decrypt(res,ct1);
	ea.decode(rvec,res);
	std::cerr << "calculation end" << std::endl; 
	std::cerr << rvec << std::endl; 

	ct1 += ct2;
	ctr = ct1;

	std::ofstream ciphers("ciphers",std::ios::binary);
	std::cerr << "size of object???"<<sizeof ct1 << std::endl; 
	std::cerr << "size of pointer"<<sizeof &ct1 << std::endl; 
	ciphers << *ct1 <<endl;
	ciphers << *ct2 <<endl;
	ciphers.close();

	std::ifstream cipherin("ciphers",std::ios::binary);
	cipherin >> ct1;
	cipherin >> ct2;
	cipherin >> ct1;
	cipherin.close();

	std::cerr << "" << std::endl; 
	std::cerr << "address ctr" << &ctr << std::endl; 
	std::cerr << "address ct1" << &ct1 << std::endl; 
	double t = GetTime();
	ctr+=ct1;
	t = GetTime() -t;
	std::cerr << "add time "<< t  << std::endl; 
	t = GetTime();
	ea.rotate(ctr,100);
	t = GetTime() -t;
	std::cerr << "rotate time "<< t  << std::endl; 
	t = GetTime();
	ea.shift(ctr,1);
	t = GetTime() -t;
	std::cerr << "shift time "<< t  << std::endl; 
	t = GetTime();
	ctr.multByConstant(V2);
	t = GetTime() -t;
	std::cerr << "mul C()*PlainVec(0) time "<< t  << std::endl; 
	sk.Decrypt(res,ctr);
	ea.decode(rvec,res);
	//std::cerr << "result: "<< rvec  << std::endl; 
	t = GetTime();
	ct1.multiplyBy(ct1);
	t = GetTime() -t;
	std::cerr << "mul C()*C() time "<< t  << std::endl; 
	sk.Decrypt(res,ctr);
	ea.decode(rvec,res);
	ctr.clear();
	//std::cerr << "result: "<< rvec  << std::endl; 
	t = GetTime();
	ct1.multByConstant(ax);
	t = GetTime() -t;
	std::cerr << "mul C()*plain time "<< t  << std::endl; 
	ctr.clear();

	sk.Decrypt(res,ctr);
	ea.decode(rvec,res);
	//std::cerr << "result: "<< rvec  << std::endl; 

        return 0;
}
