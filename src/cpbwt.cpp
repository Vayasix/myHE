#include "cpbwt.h"

//#define DEBUG_MAIN

extern cybozu::RandomGenerator rg;

void CPBWT::Client::setParam(int len, int blk, int row, int column, std::string pubkf,std::string prvkf, std::string contf)
{
	v_length = len;
	B0 = blk;
	L0 = row;
	L1 = column;
	pubk=pubkf;//just file name
	prvk=prvkf;//just file name
	cont=contf;//just file name
	setParam(L0, L1, prvk, pubk, cont);//XXX set FHE parameters
	L1 = nslots;
	v_length = L0*L1;
}

int CPBWT::Client::chkIsLongest(std::string match){
	//Elgamal::CipherText c;
	Ctxt c(*pub);
	std::ifstream ifs(match.c_str(), std::ios::binary);
	bool cc;
	int res,line;
	std::vector<long> resvec;
	ZZX RES;

	ifs >> line;
	for(int i=0; i<line; i++){
		res=0;
		ifs >> c;
		//res = prv.dec(c, &cc);
		prv->Decrypt(RES,c);
		ea->decode(resvec,RES);
		for(int i=0;i<resvec.size();i++){
			res+=resvec[i];
		}
		if(cc && res==0){
			return(0);
		}else{
		}
		c.clear();
	}
	return(-1);
}

int CPBWT::Server::retV(int idx){
	return(v[idx]);
}

void CPBWT::Server::setParam(std::string file, std::string contFile)
{
	pubk=file;
	cont=contFile;

	std::cerr<<pubk<<"\n";
	std::cerr<<cont<<"\n";
	std::cerr<<"set v\n";
	//FIXME  this is my point but maybe wrong

	std::cerr<<"read key\n";
	readPubkey(pubk,cont);
	L1=nslots;
	v_length =L1*L0;
	std::cerr<<"set v\n";
	v = (int*)calloc(sizeof(int),v_length);
	setV(v, v_length, L0, L1);
}

void CPBWT::Server::readPBWT(int m, int n, std::string pbwtfile)
{
	snps=n;
	samples=m;
	pbwt = (int *)malloc(sizeof(int)*m*n);
	std::ifstream ifs(pbwtfile.c_str());
	std::string tmp;
	char ch;
	for (int j=0;j<n;j++){
		ifs >> tmp;
		for (int i=0;i<m;i++){
			ch = tmp[i];
			if(ch=='1')
			switch(ch){
			case '0':
				pbwt[j*m+i] = 0;
				break;
			case '1':
				pbwt[j*m+i] = 1;
				break;
			}
		}
	}
}

void CPBWT::Server::makeLUTable(void)
{
	int blk = (samples+1)*pos.size(); // +1: store zero
	int tmp = sqrt(blk/8);
	while(tmp*tmp < ceil((double)blk/8)){
		tmp++;
	}
	B0 = tmp;
	L0 = B0*2;
	L1 = 8*tmp;
	v_length = L0*L1;
//	v = (int*)calloc(sizeof(int),v_length);

	std::cerr<<"B0="<<B0<<", L0="<<L0<<" ,L1="<<L1<<" blk="<<B0*L1<<"\n";
}

void CPBWT::Server::updtLUTable(void)
{
	int cnt1, cnt0;
	for(int i=0;i<pos.size();i++){
		cnt0=0;cnt1=0;
		v[i*(samples+1)] = i*(samples+1); // initialize v0		
		for(int j=0; j< samples; j++){
			if( pbwt[pos[i]*samples + j] == 0 ){
				cnt0++;
			}else{
				cnt1++;
			}
			v[i*(samples+1)+j+1] = cnt0 + i*(samples+1);
			v[i*(samples+1) + B0*L1 +j+1] = cnt1;
		}
		v[i*(samples+1) + B0*L1] = cnt0 + i*(samples+1); // initialize v1
		for(int j=0; j< samples; j++){
			v[i*(samples+1) + B0*L1 +j+1] += cnt0 + i*(samples+1);
		}
	}
	updtV(v, v_length, L0, L1);
#ifdef DEBUG
	for(int i=0;i<v_length;i++){
		std::cerr<<v[i]<<", ";
	}
	std::cerr<<"\n";
#endif
}

void CPBWT::Server::setPrevFr(){
	prev_r0 = prev_fr0;
	prev_r1 = prev_fr1;
}
void CPBWT::Server::setPrevGr(){
	prev_r0 = prev_gr0;
	prev_r1 = prev_gr1;
}
void CPBWT::Server::storePrevFr(){
	prev_fr0 = prev_r0;
	prev_fr1 = prev_r1;
}
void CPBWT::Server::storePrevGr(){
	prev_gr0 = prev_r0;
	prev_gr1 = prev_r1;
}

void CPBWT::Server::getOrgQuery(std::string& query, int index){
	std::ifstream ifs(query.c_str(), std::ios::binary);
/*
	Elgamal::CipherText c;
	CipherTextVec::iterator it;
	CipherTextVec::iterator start;
*/

	ZZ Prev_r0;
	Prev_r0 = prev_r0*(-1);
	//pub.enc(c, prev_r0, rg);
	//c.neg();
	if(index==0){
		efp = new Ctxt(*pub);//for f0
		efq = new Ctxt(*pub);//for f1
		ifs >> *efp;
		ifs >> *efq;
		efp->addConstant( Prev_r0 );
		ea->rotate(*efq,(-1)*prev_r1);
		//efp.add(c);
		//efq.resize(L1);
		//it = efq.begin();
		//start = efq.begin();
		
	}else{
		egp = new Ctxt(*pub);//for g0
		egq = new Ctxt(*pub);//for g1
		ifs >> *egp;
		ifs >> *egq;
		egp->addConstant(Prev_r0);
		ea->rotate(*egq,(-1)*prev_r1);
		//egp.add(c);
		//egq.resize(L1);
		//it = egq.begin();
		//start = egq.begin();
	}

/*
	for(int i=0;i<(L1-prev_r1);i++)
		it++;
		
	for(int i=0;i<L1;i++){
		if(i+(L1-prev_r1)==L1){
			it = start;
		}
		ifs >> c;
		*it=c;
		it++;
	}
*/
}

//FIXME later
void CPBWT::Server::compIsELongest(int offset, int flg, std::vector<Ctxt>& tmp){
/*	Elgamal::CipherText c;
	Elgamal::CipherText d;	
	Elgamal::CipherText e;
	Elgamal::CipherText res;	

	Elgamal::CipherText egp_t=egp, efp_t=efp;
	CipherTextVec egq_t, efq_t;
	egq_t.resize(L1);
	efq_t.resize(L1);
	
	pub.enc(c,0,rg);
	pub.enc(d,L0,rg);
	pub.enc(e,1,rg);

	for(int i=0;i<L1;i++){
		efq_t[(i+offset)%L1] = efq[i];
		egq_t[i] = egq[i];
	} 
	if(flg==0){
		//same f_0
		for(int i=0; i<offset;i++)
			efq_t[i] = c;
		
	}else{
		//f_0 = f_0+1
		for(int i=offset; i<L1;i++)
			efq_t[i] = c;
		efp_t.add(e);
	}

	omp_set_nested(1);
#pragma omp parallel for
	for(int i=0;i<L1;i++){
		egq_t[i].neg();
		efq_t[i].add(egq_t[i]);
		efq_t[i].mul(rand());
	}
	for(int i=0;i<L1;i++)
		c.add(efq_t[i]);

	c.add(efp_t);
	egp_t.neg();
	c.add(egp_t);

	Zn rn;
	rn.setRand(rg);
	res = c;
	res.mul(rn);
	tmp.push_back(res);

	rn.setRand(rg);
	res = c;
	res.add(d);
	res.mul(rn);
	tmp.push_back(res);

	rn.setRand(rg);
	res = c;
	d.neg();
	res.add(d);
	res.mul(rn);
	tmp.push_back(res);
*/
}

//FIXME later
void CPBWT::Server::makeIsELongest(std::string match, int thr){
/*	std::ofstream ofs(match.c_str(), std::ios::binary);
	CipherTextVec tmp;

	compIsELongest(0, 0, tmp);
	for(int i=1; i<thr; i++){
		compIsELongest(i, 0, tmp);
		compIsELongest(i, 1, tmp);
	}
	
	ofs << tmp.size() << "\n";
	random_shuffle(tmp.begin(),tmp.end());
	for(int i=0;i<tmp.size();i++){
		ofs << tmp[i];
		ofs << "\n";
	}
	*/
}

void CPBWT::Server::makeIsLongest(std::string match){
	std::ofstream ofs(match.c_str(), std::ios::binary);

	//Elgamal::CipherText c;
	//Elgamal::CipherText d;
	//Elgamal::CipherText res;
	Ctxt ct0(*pub);
	Ctxt ct1(*pub);
	Ctxt cL0(*pub);
	Ctxt res(*pub);

	ct0.clear();
	ct1.clear();
	res.clear();


//	pub.enc(c,0,rg);
//	pub.enc(d,L0,rg);
	std::vector<long> vL0(L1, L0);
	ZZX XL0;
	ea->encode(XL0,vL0);
	pub->Encrypt(cL0,XL0);// Enc( L0 L0 L0 L0 L0 L0)
//FIXME openmp
//	omp_set_nested(1);
//#pragma omp parallel for
/*	for(int i=0;i<L1;i++){
		egq[i].neg();
		efq[i].add(egq[i]);
		efq[i].mul(rand());
	}
	for(int i=0;i<L1;i++)
		c.add(efq[i]);
*/
//XXX for t1
	efq->negate();
	egq->addCtxt(*efq); // If Enc(0 0 0 0 0 0) => match
	ct1+=*egq; // If Enc(0 0 0 0 0 0) => match
//XXX for t0
//	c.add(efp);
//	egp.neg();
//	c.add(egp);
	ct0+=*efp;
	egp->negate();
	ct0+=*egp;
	
	ct0+=ct1;
	std::vector<Ctxt> tmp;

//	Zn rn;
//	rn.setRand(rg);
	ZZ Rand( rand() );
	res += ct0;
	//res.mul(rn);
	res.multByConstant( Rand );
	tmp.push_back(res);
	res.clear();

//	rn.setRand(rg);
	ZZ Rand2( rand() );
	res += ct0;
	res += cL0;
//	res.mul(rn);
	res.multByConstant( Rand2 );
	tmp.push_back(res);
	res.clear();

//	rn.setRand(rg);
	ZZ Rand3( rand() );
	res += ct0;
	cL0.negate();
	res += cL0;
	res.multByConstant( Rand3 );
	tmp.push_back(res);

	ofs << tmp.size() << "\n";
	random_shuffle(tmp.begin(),tmp.end());
	for(int i=0;i<tmp.size();i++){
		ofs << tmp[i];
		ofs << "\n";
	}
}
