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

	double SetParamT;
	double KeyGenT;
	double EncryptT;
	double EncodeT;
	double CalcT;
	double DecryptT;

	double t = GetTime();
	m = FindM(K,L,c,p, d, 0, 0);
	cout << "Setting all params....." << endl; 
	FHEcontext context(m, p, r);
	buildModChain(context, L);
	SetParamT = GetTime() - t;
	cout << "now generating key...." << endl;

	t = GetTime();
	FHESecKey sk(context);
	sk.GenSecKey(w);
	const FHEPubKey& pk = sk;
	 // actually generate a secret key with Hamming weight w
	ZZX G;
	addSome1DMatrices(sk);//for relinearization
	if(d==0){
		G=context.alMod.getFactorsOverZZ()[0];
	}else{
		G=makeIrredPoly(p,d);
	}
	cout << "Generated key" << endl;
	KeyGenT = GetTime() - t;

	//t = GetTime();
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

	std::vector<double> KEYGENv;
	std::vector<double> ENCv;
	std::vector<double> DECv;
	std::vector<double> ENCODEv;

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

	t = GetTime();
	ZZX V1,V2,V3,V4;
	ea.encode(V1,v1); ea.encode(V2,v2);
	ea.encode(V3,v3);
	EncodeT = GetTime() - t;
 
	t = GetTime();
	pk.Encrypt(ctxt1, V1);//encryption    vi--publickey-->ct1 ?
	pk.Encrypt(ctxt2, V2);//encryption    vi--publickey-->ct1 ?
	pk.Encrypt(ctxt3, V3);//encryption    vi--publickey-->ct1 ?
	pk.Encrypt(ctxt4, V4);//encryption    vi--publickey-->ct1 ?
	EncryptT = GetTime() - t;
	cout << "now calculating...." << endl;

	int times=1;
	ostringstream oss1,oss2;
	oss1 << L;
	string str1 = "/home/yu/graph/res/yu_vec_Dist_L_";
	string mid = "_K_";
	string strT = ".txt";
	str1+=oss1.str()+mid;
	oss2 << K;
	str1+=oss2.str()+strT;
	ofstream myfile(str1.c_str());

/*	string ENC = str1+"ENC";
	ofstream fENC(ENC);
	string KEYGEN = str1+"KEYGEN";
	ofstream fKEYGEN(KEYGEN);
	string DEC = str1+"DEC";
	ofstream fDEC(DEC);
	string ENCODE = str1+"ENCODE";
	ofstream fENCODE(ENCODE);
*/

//how many times calc is conducted??
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
			t = GetTime();
			ctxt1.multiplyBy(ctxt2);
			ctxt3.multiplyBy(ctxt2);
//			ctxt1.addCtxt(ctxt2);

			CalcT = GetTime() - t;
			if( ctxt1.isCorrect() ){
				ContainsError=false;	
				cout << "Lv "<< L << "Ctxt1 ["<< j <<"]:	O" << endl; 
			}else{
				ContainsError=true;
				cout << "Lv "<< L << "Ctxt1 [" << j <<"]:	X" << endl; 
			}

			if( ctxt3.isCorrect() ){
				ContainsError=false;	
				cout << "Lv " << L <<"Ctxt3 ["<< j <<"]:	O" << endl; 
			}else{
				ContainsError=true;
				cout << "Lv " << L <<"Ctxt3 [" << j <<"]:	X" << endl; 
			}
		}//for end
			
		if(ContainsError){
			cout << "error" << endl; 
			myfile << "0.0";
		}else{
			myfile << CalcT;
		}
		cout << "finally," << endl; 
		if( ctxt1.isCorrect() ){
			cout <<"Ctxt1 [" << times <<"] mult. can decrypt correctly :D OOOOO" << endl; 
			t = GetTime();
			sk.Decrypt(result,ctxt1);
			DecryptT = GetTime() - t;
			cout << "Decryption time: " << t << " seconds" << endl;
		}else{
			cout << "Ctxt1 XXXXX cannot decrypt correctly XXXXX" << endl; 
		}

		if( ctxt3.isCorrect() ){
			cout <<"Ctxt3 [" << times <<"] mult. can decrypt correctly :D OOOOO" << endl; 
			t = GetTime();
			sk.Decrypt(result,ctxt3);
			DecryptT += GetTime() - t;
			cout << "Decryption time: " << t << " seconds" << endl;
		}else{
			cout << "Ctxt3 XXXXX cannot decrypt correctly XXXXX" << endl; 
		}


		cout << "\n\n" << endl; 
		ContainsError=false;

	//SetParamT;
	KEYGENv.push_back(KeyGenT);
	ENCODEv.push_back(EncodeT);
	ENCv.push_back(EncryptT);
	DECv.push_back(DecryptT);

	}// for times end
	myfile << endl;
	for(int i=0; i < KEYGENv.size(); i++){
		myfile << KEYGENv[i];
		if(i==KEYGENv.size()-1){
			break;
		}
		myfile << ",";
	}
	myfile << endl;

	for(int i=0; i < ENCODEv.size(); i++){
		myfile << ENCODEv[i];
		if(i==ENCODEv.size()-1){
			break;
		}
		myfile << ",";
	}
	myfile << endl;

	for(int i=0; i < ENCv.size(); i++){
		myfile << ENCv[i];
		if(i==ENCv.size()-1){
			break;
		}
		myfile << ",";
	}
	myfile << endl;

	for(int i=0; i < DECv.size(); i++){
		myfile << DECv[i];
		if(i==DECv.size()-1){
			break;
		}
		myfile << ",";
	}
	myfile << endl;
	myfile.close();
}

//int main(int argc, char **argv)
int main(void)
{
	    /* On our trusted system we generate a new key
	     *      * (or read one in) and encrypt the secret data set.
	     *           */
/*parameter setting*/
	long m=0, p=2, r=1; // Native plaintext space
        // Computations will be 'modulo p'
	long L=5;          // Levels(number of ciphertext-primes that we want to support)
	long c=2;           // Columns in our key switching matrices
	long w=64;          // Hamming weight of secret key
	long d=1;           // field of extention ( #of calulations???? )
	long s=0;           // 
	long security = 128;
	int Lmax =(int)L;  //   # of multiplications
	long fL=3;
	//L=atoi(argv[1]);
	//security=atoi(argv[2]);
	for(int i=1;i<=60;i++){
		L=i;
	//	L=fL;
		Lmax=L;
		TestIt(m,p,r,L,c,w,d,s,security,Lmax);
	}
	return 0;
}

