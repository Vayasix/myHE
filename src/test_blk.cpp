#include <iostream> 
#include <cmath> 
#include <fstream> 


int main(void){
	//int M=2185;
	int Mvals[3]={2185,100000,200000};
	int Dvals[5]={1,5,10,20,50};
	std::ofstream myfile("vals.txt");
		myfile << "M,D,L0,L1,L0*L1,blk" << std::endl;
	for (int index=0;index<sizeof(Mvals)/sizeof(Mvals[0]);index++){
		int M=Mvals[index];

		for(int j=0;j<sizeof(Dvals)/sizeof(Dvals[0]);j++){
		int D=Dvals[j];
		int blk=(M+1)*D;
		int tmp=sqrt(blk/8);
		int L0=0,L1=0,B0=0;
		std::cerr << "Case (M,D)=" << Mvals[index] << "," << Dvals[j] << std::endl; 
		std::cerr<<"blk= "<< blk<<" , (double) tmp= "<< sqrt(blk/8.0)<< " tmp ="     << tmp<<",  ceil(double)blk/8="<< ceil((double)blk/8)<<" samples M=" << M     << "\n";

		while(tmp*tmp < ceil((double)blk/8)){
			tmp++;
		}

		B0 = tmp;
		L0 = B0*2;
		L1 = 8*tmp;
		std::cerr<<"B0="<<B0<< " v_length=" << L0*L1 <<" , L0="<<L0<<" ,L1="<<L1<<" blk="<<B0*L1<<"\n";
		myfile << M <<"," << D << "," << L0<< "," << L1 << "," << L0*L1 << "," << blk<< std::endl;
		}
	}
	return 0;
}

