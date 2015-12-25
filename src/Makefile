TOPDIR:=$(realpath $(dir $(lastword $(MAKEFILE_LIST))))/
#CC = g++
CC = c++
$(info $(TOPDIR))

# CFLAGS=-O3  for crypto-PBWT

CFLAGS = -g -O2
# -std=c++11
# -std=c++11 -DFHE_THREADS -DFE_DCRT_THREADS

GMP=-lgmp
#LDLIBS = -L/usr/local/lib -L/usr/local/include -lntl $(GMP) -lm -lrt -lstdc++
LDLIBS = -L/usr/local/lib -L/usr/local/include -lntl $(GMP) -lm -lstdc++

CFLAGS+= -I$(TOPDIR)include -I$(TOPDIR)../../cybozulib/include/ -I$(TOPDIR)../../mie/include -I$(TOPDIR)../../xbyak/ -I$(TOPDIR)../../Lifted-ElGamal/include/ -I$(TOPDIR)../include/ -I$(TOPDIR)../../HElib/src -I/usr/local/include -fopenmp

LDFLAGS+= -lgmp -lgmpxx -lcrypto
##
SERVER_OBJS=rot.o cpbwt.o comm.o server.o
CLIENT_OBJS=rot.o cpbwt.o comm.o client.o
CPBWT_OBJS=rot.o cpbwt.o cpbwt_main.o
ROT_OBJS=rot.o

all: server client cpbwt

clean:
	rm server client $(SERVER_OBJS) $(CLIENT_OBJS) *~

.SUFFIXES: .cpp
##

./%: %.cpp
	$(CC) $(CFLAGS) -o $@ $< ../../HElib/src/fhe.a $(LDLIBS) 

.cpp.o:
	$(CXX) -c $< -o $@ $(CFLAGS) -fopenmp
	@echo Hello!!

cpbwt: $(CPBWT_OBJS)
	$(CXX) $(CFLAGS) $(CPBWT_OBJS) ../../HElib/src/fhe.a -o $@  $(LDLIBS) $(LDFLAGS) -fopenmp
	mv cpbwt $(TOPDIR)../bin/

server: $(SERVER_OBJS)
	$(CXX) $(CFLAGS) $(SERVER_OBJS) ../../HElib/src/fhe.a -o $@ $(LDLIBS) $(LDFLAGS) -fopenmp
	mv server $(TOPDIR)../bin/

client: $(CLIENT_OBJS)
	$(CXX) $(CFLAGS) $(CLIENT_OBJS) ../../HElib/src/fhe.a -o $@ $(LDLIBS) $(LDFLAGS) -fopenmp
	mv client $(TOPDIR)../bin/

rot:  $(ROT_OBJS)
	$(CXX) $(CFLAGS) $(ROT_OBJS) ../../HElib/src/fhe.a -o $@ $(LDLIBS) $(LDFLAGS) 
	mv rot $(TOPDIR)../bin/
