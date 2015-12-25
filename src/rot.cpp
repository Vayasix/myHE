#include <cybozu/option.hpp>
#include "rot.h"
#include "FHE.h"
#include "EncryptedArray.h"
#include <NTL/lzz_pXFactoring.h>
#include <fstream>
#include <sstream>
#include <string>
#include <iostream>
#include <sys/time.h>

cybozu::RandomGenerator rg;

//#define DEBUG_MAIN

void ROT::SysInit()// param for encryption
{
	/*
	long m=0, p=2, r=20; // Native plaintext space
	// Computations will be 'modulo p'
	long L=3;          // Levels(number of ciphertext-primes that we want to support)
	long c=2;           // Columns in our key switching matrices
	long w=64;          // Hamming weight of secret key
	long d=1;           // field of extention ( #of calulations???? )
	long s=0;           // 
	long security = 128;
	m = FindM(K,L,c,p, d, s, 0);
	cout << "Setting all params....." << endl;
	context(m, p, r);
	buildModChain(context, L);
	*/
}

// just initialization not assign
void ROT::Server::setV(int* input, int length, int row, int column)
{
	v_length = length;
	L0 = row;
	L1 = column;
	v0 = (int*)malloc(sizeof(int)*v_length);
	v1 = (int*)malloc(sizeof(int)*v_length);

	std::cerr << "server setV L0="<<L0 <<" L1="<<L1 << "v_length="<< v_length << std::endl; 
	std::vector<long> vec0,vec1;
	ZZX v0X,v1X;

	std::cerr << "In setV ea-size->"<< ea->size() << std::endl; 
	//context->zMStar.printout();
	for(int i = 0;i < v_length;i++){
		v0[i] = input[i]/L1;//結局これを連結するので暗号化は最後でよい
		v1[i] = input[i]%L1;//likewise

		if(i==0){
			vec0.push_back(v0[i]);
			vec1.push_back(v1[i]);
			continue;
		}

		if(i%L1!=0 && i!=0){
			vec0.push_back(v0[i]);
			vec1.push_back(v1[i]);
		}else if(i%L1==0 && i!=0){
			vv0.push_back(vec0);
			vv1.push_back(vec1);
			ea->encode(v0X,vec0);
			ea->encode(v1X,vec1);
			V0.push_back(v0X);
			V1.push_back(v1X);

			vec0.clear();
			vec1.clear();
			vec0.push_back(v0[i]);
			vec1.push_back(v1[i]);
		}
	}
		vv0.push_back(vec0);
		vv1.push_back(vec1);
		ea->encode(v0X,vec0);
		ea->encode(v1X,vec1);
		V0.push_back(v0X);
		V1.push_back(v1X);
}


void ROT::Server::updtV(int* input, int length, int row, int column)
{
//	std::cerr << "In updtV===> ea-zie===" << ea->size() << std::endl; 
//	context->zMStar.printout();
	std::vector<long> vec0,vec1;
	ZZX v0X,v1X;
	vv0.clear();
	vv1.clear();
	V0.clear();
	V1.clear();

	for(int i = 0;i < v_length;i++){
		v0[i] = input[i]/L1;
		v1[i] = input[i]%L1;
	
		if(i==0){
			vec0.push_back(v0[i]);
			vec1.push_back(v1[i]);
			continue;
		}
//assume L1 is always GT 0
		if(i%L1!=0 && i!=0){
			vec0.push_back(v0[i]);
			vec1.push_back(v1[i]);
		}else if(i%L1==0 && i!=0){
			vv0.push_back(vec0);
			vv1.push_back(vec1);
			ea->encode(v0X,vec0);
			ea->encode(v1X,vec1);
			V0.push_back(v0X);
			V1.push_back(v1X);

			vec0.clear();
			vec1.clear();
			vec0.push_back(v0[i]);
			vec1.push_back(v1[i]);
		}
	}
		vv0.push_back(vec0);
		vv1.push_back(vec1);
		ea->encode(v0X,vec0);
		ea->encode(v1X,vec1);
		V0.push_back(v0X);
		V1.push_back(v1X);
}

void ROT::Server::readPubkey(std::string& pubFile, std::string& contFile)
{
		std::cerr << "context and pub setting ..." << std::endl;
	{fstream keyFile(contFile.c_str(),fstream::in|fstream::binary);
		unsigned long m1, p1, r1;
		vector<long> gens,ords;
		readContextBase(keyFile,m1,p1,r1,gens,ords);
		context = new FHEcontext(m1,p1,r1,gens,ords);
		//FHEcontext tmpcont(m1,p1,r1,gens,ords);
		std::cerr << "context setting ..." << std::endl;
		keyFile >> *context;
		//keyFile >> tmpcont;
		//*context = tmpcont;
		keyFile.close();
	}
	std::cerr << "context setting end" << std::endl; 
	pub = new FHEPubKey(*context);
	Load(*pub, pubFile);
	std::cerr << "public key setting end" << std::endl; 
	ea = new EncryptedArray(*context);
	std::cerr << "ea-size() ==>"<< ea->size() << std::endl; 
	nslots = ea->size(); 
	std::cerr << "nslots ==>"<< nslots << std::endl; 
}

void ROT::Server::getResult(std::string& query, int ran0, int ran1)
{
	//Elgamal::CipherText et0;
	//CipherTextVec et1;
	ofstream rotres("pcrotres",std::ios::app);
	Ctxt et0(*pub);
	Ctxt et1(*pub);
	et0.clear();
	et1.clear();

	{fstream ifs(query.c_str(), fstream::in);
		ifs >> et0;
		ifs >> et1;
		ifs.close();
	}
	//ZZX V[L0];
	

	//Elgamal::CipherText a;
	/*for(int i=0;i<L1;i++){
		ifs >> a;
		et1.push_back(a);
	}*/
	//FIXME use resize!!!
	res_v0.clear();
	res_v1.clear();
	Ctxt a(*pub);
	a.clear();
	for(int i=0;i<L0*2;i++){
	//	res_v0.resize(L0*2);
	//	res_v1.resize(L0*2);
		res_v0.push_back(a);
		res_v1.push_back(a);
	}

	int L, r, tmpr=0, ran;
//	int *v;
	std::vector< vector<long> > vv;
	std::vector< ZZX > V;

	double rotTime= GetTime();
	double pretime= 0.0;
	for(int x=0;x<2;x++){
		if(x==0){
		//	v=v0;
			vv = vv0;
			V=V0;
			L=L0;
			ran=ran0;
		}else{
		//	v=v1;
			vv = vv1;
			V=V1;
			L=L1;
			ran=ran1;
		}
		r = ran%L;
		//FIXME remove  when polynomial representation finished
		double t=GetTime();
		for(int i=0;i<vv.size();i++){
			for(int j=0;j<vv[i].size();j++){
				vv[i][j]=(vv[i][j]+r)%L;
			}
			ea->encode(V[i],vv[i]);
		}
		t=GetTime()-t;
		pretime+=t;
		//std::cerr << "magambo time " << t << std::endl; 
//		FIXME openmp
//		omp_set_num_threads(core);
//		omp_set_nested(1);
//		#pragma omp parallel for
		Ctxt ct1(*pub);
		Ctxt ct0(*pub);
		Ctxt dt0(*pub);
		Ctxt dt1(*pub);

		ea->rotate(et1,(-1)*prev_r1);
		for(int i=0;i<L0;i++){
		/*	
			Elgamal::CipherText c;
			Elgamal::CipherText d;
			Elgamal::CipherText e;
			for(int j=0;j<L1;j++){
				int k = v[i*L1+j];
				k += r;
				k = k%L;
				c = et1[ (j+prev_r1)%L1 ];
				c.mul(k);
				e.add(c);
			}
		*/
			ct0.clear();
			ct1.clear();
			dt0.clear();
			dt1.clear();
			
			ct0+=et0;  //for t0
			ct1+=et1;  //for t1
			dt0+=et0;  //for t0
			dt1+=et1;  //for t1

			//c+=egq();  //for t1
			ZZ Prev_r0 = to_ZZ( (-1)*i-prev_r0 );
			ZZ Prev_r0_L0 =  to_ZZ( (-1)*i-prev_r0+L0 );
			ZZ Rand = to_ZZ( rand() );
			//ZZ RandLUV( r );

	ct0.addConstant( Prev_r0 );
	ct0.multByConstant( Rand );
	//ct1.multByConstant( V[i]+RandLUV );//FIXME consider mod via polynomial representation !
	ct1.multByConstant( V[i] );//FIXME should consider mod via polynomial representation !
	ct1+=ct0;
	if(!ct1.isCorrect()){
		std::cerr << "ddie" << std::endl; 
		exit(1);}

	dt0.addConstant( Prev_r0_L0 );
	dt0.multByConstant( Rand );
	//dt0.multByConstant( V[i]+RandLUV );//FIXME consider mod via polynomial representation!
	dt1.multByConstant( V[i] );//FIXME should consider mod via polynomial representation !
	dt1+=dt0;
	if(!dt1.isCorrect()){
		std::cerr << "ddie" << std::endl; 
		exit(1);}
//			Zn rn;
//			pub.enc(c,(i + prev_r0),rg);
//			c.neg();
//			c.add(et0);
//			rn.setRand(rg);
//			c.mul(rn);  
//			c.add(e); 

//			pub.enc(d,(i + prev_r0 - L0),rg); //ok
//			d.neg(); //ok
//			d.add(et0); //ok
//			rn.setRand(rg);
//			d.mul(rn); // ok
//			d.add(e);

			int pos = prev_r0+i;
			if(L0<=pos){
				pos = pos%L0;
			}
			int sel = rg.get32()%2;

			if(sel==0){
				switch(x){
				case 0:
					res_v0[2*pos] = ct1;
					res_v0[2*pos+1] = dt1;
					break;
				case 1:
					res_v1[2*pos] = ct1;
					res_v1[2*pos+1] = dt1;
					break;
				}
			}else{
				switch(x){
				case 0:
					res_v0[2*pos] = dt1;
					res_v0[2*pos+1] = ct1;
					break;
				case 1:
					res_v1[2*pos] = dt1;
					res_v1[2*pos+1] = ct1;
					break;
				}
			}
	    }
		if(x==0)
			tmpr = r;
		else
			prev_r1 = r;
	}
	rotTime= GetTime()-rotTime;
	std::cerr << "entir ROT time is "<< rotTime << std::endl; 
	std::cerr << "ROT wthout preptime is "<< rotTime-pretime << std::endl; 
	rotres << rotTime << "," << rotTime-pretime << std::endl;
	rotres.close();
	prev_r0 = tmpr;
	//v=NULL;
	vv.clear();
}

void ROT::Server::makeResFile(std::string& result)
{
	//std::ofstream ofs(result.c_str(), std::ios::binary);
	{fstream ofs( result.c_str(),fstream::out|fstream::binary|fstream::trunc );
	//Save(contFile,*context);
		for(int i=0;i<2*L0;i+=2){
			ofs << res_v0[i]   << std::endl;
			ofs << res_v0[i+1] << std::endl;
			ofs << res_v1[i]   << std::endl;
			ofs << res_v1[i+1] << std::endl;
		}	
		ofs.close();
	}
}

void ROT::Client::setParam(int row, int column, std::string& prvFile, std::string& pubFile, std::string& contFile)
 {		
	L0 = row;
	L1 = column;
	
	long m=0, p=2, r=20; // Native plaintext space
	// Computations will be 'modulo p'
	long L=4;          // Levels(number of ciphertext-primes that we want to support)
	long c=2;           // Columns in our key switching matrices
	long w=64;          // Hamming weight of secret key
	long d=1;           // field of extention ( #of calulations???? )
	long s=L1;           // 
	long security = 128;
	//long ptxtSpace = power_long(p,r);
	/* FIXME
	 *  ミニマムスロットから探せるように
	 *  hash function を作っておくとよい
	 *  findM を逃れるため！！！
	 *  
	 * */
	m = FindM(security,L,c,p, d, s, 0);
	//FIXME practically avoid findM
	cout << "setting all params for FHE" << endl; 
	context = new FHEcontext(m,p,r);
	buildModChain(*context, L,c);

	prv = new FHESecKey(*context);
	prv->GenSecKey(w);
	pub = new FHEPubKey(*context);//XXX maybe wrong
	pub = prv;// maybe wrong
	addSome1DMatrices(*prv);//for relinearization
	ea  = new EncryptedArray(*context);

	{fstream keyFile( contFile.c_str(),fstream::out| fstream::binary|fstream::trunc );
	//Save(contFile,*context);
		writeContextBase(keyFile, *context);//write context -> pubFile
		keyFile << *context;
		keyFile.close();
	}
	Save(prvFile,*prv);
	Save(pubFile,*pub);
	//contFile << *context << endl;
	//prvFile  << *prv << endl;
	//pubFile << *pub << endl;

	nslots = ea->size();
	L1 = nslots;
	fprintf(stderr,"make privateKey=%s, publicKey=%s\n", prvFile.c_str(), pubFile.c_str());


//	Load(contFile, context);
//	Load(pub, pubFile);
//	Load(prv, prvFile);

	/*	if(L0<L1)
			prv.setCache(0, L1+1); // set cache for prv
		else
			prv.setCache(0, L0+1);
	*/
}

//wirte query into the files 
void ROT::Client::makeQuery(std::string& query,int t0, int t1)//make f,g vector
{
	{fstream ofs(query.c_str(), fstream::out|fstream::binary|fstream::trunc);
	std::vector<long> t0vec,t1vec;//for packed-cipher
	//tmp.resize(L1*L0);//origin was L1
/*
	if(d==0){
		G=context.alMod.getFactorsOverZZ()[0];
	}else{
		G=makeIrredPoly(p,d);
	}
*/ 
	//E L1 => \ell
	//  = ea.size()
	for(int i=0;i<L1; i++){
		if(i==t1){
			t1vec.push_back(1);
		}else{
			t1vec.push_back(0);
		}
		t0vec.push_back(t0);
	}
	std::cerr << "query plain vector was created " << std::endl; 
	std::cerr << "t0,t1 = "<< t0 << "," << t1 << std::endl; 
	ZZX V0,V1;
	//std::cerr << t0vec << std::endl; 
	//std::cerr << t1vec << std::endl; 
	//
	ea->encode(V0,t0vec);
	ea->encode(V1,t1vec);

	Ctxt c_t0(*pub);
	Ctxt c_t1(*pub);
	std::cerr << "encode end !!!!!!!!!! " << std::endl; 
	pub->Encrypt(c_t0, V0);
	pub->Encrypt(c_t1, V1);
	//ea->encrypt(*c_t1, *pub, t1vec);
	//ea->encrypt(*c_t0, *pub, t0vec);
	std::cerr << "encrypt end !!!!!!!!!! " << std::endl; 
	ofs << c_t0 << std::endl;
	ofs << c_t1 << std::endl;
	ofs.close();
	}
/*
	int m=0;
	omp_set_num_threads(core);
	omp_set_nested(1);
#pragma omp parallel for
	for(int i=0;i<L1;i++){
		Ctxt d(pub);
		if(i==t1){
			m=1;
		}else{
			m=0;
		}
		pub.enc(d, m, rg);
		tmp[i]=d;
		//		ofs << c;
		//		ofs << "\n";
	}

	for(int i=0;i<L1;i++){
		ofs << tmp[i];
		ofs << "\n";
	}
*/

}

void ROT::Client::decResult(std::string& result, int t_0, int t_1)
{
	//Elgamal::CipherText c, d;
	Ctxt c(*pub);
	Ctxt d(*pub);
	{fstream ifs(result.c_str(), fstream::in|fstream::binary);

	vector<long> x, y;
	ZZX X,Y;

	bool xc, yc;
	std::cerr << "[[[ "<<t_0<<" ]]]" << std::endl; 
	for(int i=0;i<=t_0;i++){
		ifs >> c;
		ifs >> d;
		if(i == t_0){
		//	x = prv.dec(c, &xc);
		//	y = prv.dec(d, &yc);
			prv->Decrypt(X,c);
			prv->Decrypt(Y,d);
			ea->decode(x,X);
			ea->decode(y,Y);
			if(x[t_1]<L0 && xc){
				t0=x[t_1];
				if(y[t_1]<L0 && yc){					
					std::cerr<<"error(t0): ";
					std::cerr<<x[t_1]<<","<<y[t_1]<<"\n";
				}				
			}else{
				t0=y[t_1];
			}		
		}

		ifs >> c;
		ifs >> d;
		if(i == t_0){
			//x = prv.dec(c, &xc);
			//y = prv.dec(d, &yc);
			prv->Decrypt(X,c);
			prv->Decrypt(Y,d);
			ea->decode(x,X);
			ea->decode(y,Y);
			if(x[t_1]<L1 && xc){
				t1=x[t_1];
				if(y[t_1]<L1 && yc){					
					std::cerr<<"error(t1): ";
					std::cerr<<x[t_1]<<","<<y[t_1]<<"\n";
				}				
			}else{
				t1=y[t_1];
			}		
		}
	}
	ifs.close();
	}
}

#ifdef DEBUG_MAIN
int main(int argc, char** argv)
{
	ROT::SysInit();

	ROT::Client c;
	std::string prvk = "prvkey";
	std::string pubk = "pubkey";
	std::string contk = "context";
	c.core=1;

	int row=30, column=100;
	c.setParam(row, column, prvk, pubk,contk);

	ROT::Server s;
	s.core=1;
	int len = row*column;
	int* input = (int*)malloc(sizeof(int)*len);
	for(int i=0;i<len;i++){
		input[i] = rand()%len;
		std::cerr<<input[i]<<",";
		std::cerr<<"  ";
	}

	int itr=10;
	int out=0;
	std::cerr<<"\n";
	for(int i=0;i<itr+1;i++){
		out = input[out];
		std::cerr<<out<<"\n";
	}

	s.readPubkey(pubk,contk);
	column=s.nslots;
	s.L1=s.nslots;
	len = row*column;
	s.v_length = row*column;
	
	std::cerr << "pubkey and context end" << std::endl; 
	s.setV(input, len, row, column);
	std::cerr << "setV end" << std::endl; 

	std::string query = "query";
	std::cerr << "Let us making query ! " << s.nslots <<std::endl; 
	c.makeQuery(query, 0,0);// query into the file query!!!!!
	std::cout << "############  clients  query generating done" << std::endl; 

	s.getResult(query, 999,1234);
	std::cout << "servers calculation end" << std::endl; 
	std::string result = "result";
	s.makeResFile(result);
	std::cout << "############   servers make result file done" << std::endl; 
	c.decResult(result, 0,0);
	std::cout << "############   users decryption done" << std::endl; 
	std::cerr<<"\n"<<c.t0<<","<<c.t1<<"\n";


	std::cout << "communication "<< itr-1 << "times below"<< std::endl; 
	for(int i=0;i<itr-1;i++){
		c.makeQuery(query, c.t0%30, c.t1%168);
		std::cout << "client made query" << std::endl; 
		s.getResult(query, rand(), rand());
		std::cout << "Server calculated based on client's query" << std::endl; 
		s.makeResFile(result);
		std::cout << "Server wrote its result into the file" << std::endl; 
		c.decResult(result, c.t0%30,c.t1%168);
		std::cout << "Clients get result !!!!!!!!!!!!!" << std::endl; 
		std::cerr<<c.t0<<","<<c.t1<<"\n";
	}

	c.makeQuery(query, c.t0%30, c.t1%168);
	std::cout << "client generated  query" << std::endl; 
	std::cout << "Server start calculations based on client's query" << std::endl; 
	s.getResult(query, 0, 0);
	std::cout << "Server write its result into the file" << std::endl; 
	s.makeResFile(result);
	std::cout << "Clients get result !!!!!!!!!!!!!" << std::endl; 
	c.decResult(result, c.t0%30,c.t1%168);
	std::cerr<<c.t0<<","<<c.t1<<"\n";
	std::cerr<<c.t0*column+c.t1<<"\n";
	
	return(0);

}

#endif
