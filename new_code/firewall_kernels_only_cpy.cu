#include <iostream>
#include <cuda_runtime.h>
#include <stdio.h>
#include <netinet/in.h>
extern "C" {
#include "firewall_kernels.h"
}
#include "rules.h"
__global__ void process_pkt1(char* input_buf,
                             char* output_buf,
                             int* len,
                             int num_pkts,
                             int buf_len) {
    int tx = threadIdx.x + blockIdx.x * blockDim.x;

    if (tx < num_pkts) {
        int pkt_start = len[tx];
        int pkt_end = len[tx + 1];
        int pkt_len = pkt_end - pkt_start;

        // Copy the packet data from input_buf to output_buf
        for (int i = 0; i < pkt_len; i++) {
            output_buf[pkt_start + i] = input_buf[pkt_start + i];
        }
    }
}

void run_firewall(char* input_buf,
                  char* output_buf,
                  int* len,
                  int num_pkts,
                  int buf_len,
                  unsigned long* rules,
                  int num_lines,
                  unsigned int* nat_table,
                  unsigned long* nat_set) {
    int* d_len;

    cudaMalloc((void**)&d_len, (num_pkts + 1) * sizeof(int));
    cudaMemcpy(d_len, len, (num_pkts + 1) * sizeof(int), cudaMemcpyHostToDevice);

    // Launch process_pkt1 kernel with appropriate block and thread configuration
    int threads_per_block = 64;  // You can adjust this as needed
    int num_blocks = (num_pkts + threads_per_block - 1) / threads_per_block;
    process_pkt1<<<num_blocks, threads_per_block>>>(input_buf, output_buf, d_len, num_pkts, buf_len);
    cudaDeviceSynchronize();

    // Copy the result back to the host
    // cudaMemcpy(output_buf, d_output_buf, buf_len * sizeof(char), cudaMemcpyDeviceToHost);

    // Free allocated device memory
    cudaFree(d_len);
}