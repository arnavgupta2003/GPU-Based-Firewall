# Gencode arguments
SMS ?= 35 37 50 52 60 61 70 75 80 86

ifeq ($(SMS),)
$(info >>> WARNING - no SM architectures have been specified - waiving sample <<<)
SAMPLE_ENABLED := 0
endif

ifeq ($(GENCODE_FLAGS),)
# Generate SASS code for each SM architecture listed in $(SMS)
$(foreach sm,$(SMS),$(eval GENCODE_FLAGS += -gencode arch=compute_$(sm),code=sm_$(sm)))
# Generate PTX code from the highest SM architecture in $(SMS) to guarantee forward-compatibility
HIGHEST_SM := $(lastword $(sort $(SMS)))
ifneq ($(HIGHEST_SM),)
GENCODE_FLAGS += -gencode arch=compute_$(HIGHEST_SM),code=compute_$(HIGHEST_SM)
endif
endif


run: main.o firewall.o rules.o nat.o
	nvcc -o run main.o firewall.o rules.o nat.o -lrt -lnetmap -lcudart -lstdc++

main.o: bridge.c firewall_kernels.h rules.h nat.h
	nvcc -I/home/nsl/Developer/netmap/sys -I/home/nsl/Developer/netmap/apps/include -I/home/nsl/Developer/netmap/libnetmap bridge.c -c -o main.o -lrt -lnetmap

#device.o: firewall.o nat.o rules.o
#	nvcc --device-link firewall.o nat.o rules.o -o device.o

firewall.o: firewall_kernels.cu
	nvcc firewall_kernels.cu -c -L/usr/local/cuda -I/usr/local/cuda/include -o firewall.o -lcudart -lstdc++

rules.o: rules.cu rules.h
	nvcc rules.cu -c -L/usr/local/cuda -I/usr/local/cuda/include -o rules.o -lcudart -lstdc++

nat.o: nat.cu nat.h
	nvcc nat.cu -c -L/usr/local/cuda -I/usr/local/cuda/include -o nat.o -lcudart -lstdc++
