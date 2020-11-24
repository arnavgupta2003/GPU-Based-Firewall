CC=gcc
NCC=nvcc
LDFLAGS=/usr/local/cuda-11.0
LDLIBS=-lcudart -lstdc++
IFLAGS=/usr/local/cuda-11.0/include
CFLAGS=-L$(LDFLAGS) -I$(IFLAGS)
run: main.o nat.o
	$(CC) -o run main.o nat.o $(CFLAGS) $(LDLIBS)

main.o: main.c b.h
	$(CC) $(CFLAGS) -c -o main.o main.c

nat.o: nat.cu b.h
	$(NCC) -c -o nat.o nat.cu
