#include <iostream>
#include <fstream>
#include <cybozu/random_generator.hpp>
#include <cybozu/crypto.hpp>
#include "EncryptedArray.h"
#include <NTL/lzz_pXFactoring.h>

#if defined(_WIN64) || defined(__x86_64__)
#define USE_MONT_FP
#endif

#include <math.h>

#define uint unsigned int

//#include<sys/time.h>
#include<sys/timeb.h>
//#include<omp.h>

//struct CipherTextVec : public std::vector< Ctxt, Ctxt(pub) > {};

namespace ROT{
	void SysInit();

	template<class T>
	bool Load(T& t, const std::string& name, bool doThrow = true)
	{/*
		std::ifstream ifs(name.c_str(), std::ios::binary);
		if (!ifs) {
			if (doThrow) throw cybozu::Exception("Load:can't read") << name;
			return false;
		}
		if (ifs >> t) return true;
		if (doThrow) throw cybozu::Exception("Load:bad data") << name;
		return false; */
		{fstream keyFile( name.c_str(), fstream::in );
			keyFile >> t;
			keyFile.close();
		}
	}
	
	template<class T>
	void Save(const std::string& name, const T& t)
	{
		//std::ofstream ofs(name.c_str(), std::ios::binary);
		//ofs << t;
		{fstream keyFile( name.c_str(),fstream::out| fstream::trunc );
			keyFile << t;
			keyFile.close();
		}
	}

	class Server{
//		int *v0, *v1;
//		std::vector< vector<long> > vv0,vv1;
//		std::vector< ZZX > V0,V1;
//		std::vector< Ctxt > Ctxts;
//		int v_length;
//		int L0, L1;
		//CipherTextVec res_v0, res_v1;//vector ( packed-ciphertext )
		std::vector<Ctxt> res_v0, res_v1;//vector ( packed-ciphertext )
//	public:
	protected:
		FHEcontext *context;
		EncryptedArray *ea;
		FHEPubKey *pub;
		int prev_r0, prev_r1;
	public:
		int *v0, *v1;
		std::vector< vector<long> > vv0,vv1;
		std::vector< ZZX > V0,V1;
		std::vector< Ctxt > Ctxts;
		int v_length;
		int L0, L1;
		int core;
		long nslots;
		void setV(int* input, int length, int row, int column);
		void updtV(int* input, int length, int row, int column);
		void readPubkey(std::string& pubFile, std::string& contFile);
		void getResult(std::string& query, int ran0, int ran1); //query includes ciphertext t0 and a vector of ciphertexts t1. 
		void makeResFile(std::string& result);
		Server(){
			prev_r0=0;
			prev_r1=0;
		}
	};

	class Client{
		int L0, L1;
	protected:
		FHEcontext *context;
		EncryptedArray *ea;
		FHEPubKey *pub;
		FHESecKey *prv;
	public:
		int core;
		long nslots;
		int t0, t1;
		void setParam(int row, int column, std::string& prvf, std::string& pupf, std::string& contf);
		void makeQuery(std::string& query, int t0, int t1);
		void decResult(std::string& result, int t_0, int t_1);
	};
}

