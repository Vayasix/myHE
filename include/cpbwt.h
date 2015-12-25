#include "rot.h"

namespace CPBWT{
	class Server : public ROT::Server
	{
		int prev_fr0, prev_fr1;
		int prev_gr0, prev_gr1;
		int *pbwt;
		int *v; //lookuptables FIXME should be encrypted Ctxt packed-ciphertext?????
		Ctxt *efq, *egq;// packed Cipher-Text
		Ctxt *efp, *egp;// also packed Cipher-Text   move to ROT
	public:
		std::string pubk;
		std::string cont;
		int snps, samples;
		int v_length, B0, L0, L1;
		std::vector<int> pos;
		int retV(int idx);
		void readPBWT(int m, int n, std::string pbwt); // m: row (num of samples), n: column (snp positions)
		void setParam(std::string pubkey_name,std::string context_name);
		void updtLUTable(void);
		void makeLUTable(void);
		void setPrevFr();
		void setPrevGr();
		void storePrevFr();
		void storePrevGr();
		void getOrgQuery(std::string& query, int index); //index == 0 ? f : g
		void makeIsLongest(std::string match);
		void makeIsELongest(std::string match, int thr);
		void compIsELongest(int offset, int flg, std::vector<Ctxt>& tmp/*packedCtxt*/);

		Server(){
			prev_fr0=0; prev_fr1=0;
			prev_gr0=0; prev_gr1=0;
		}
	};

	class Client : public ROT::Client
	{
		using ROT::Client::setParam;
	public:
		std::string prvk;
		std::string pubk;
		std::string cont;
		int samples;
		int v_length, B0, L0, L1;
		void setParam(int len, int blk, int row, int column, std::string pubkf, std::string prvkf, std::string contf);
		int chkIsLongest(std::string match);
	};
}
