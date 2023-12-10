#include <cuda_runtime.h>
#include <iostream>
#include <chrono>

int main() {
    const int arraySize =  1024 * 1024 * 1024;  // 1 GB

    // Allocate and initialize the array on the CPU
    float* hostArray = new float[arraySize];
    for (int i = 0; i < arraySize; ++i) {
        hostArray[i] = static_cast<float>(i);
    }

    // Allocate device memory
    float* deviceArray;
    cudaMalloc((void**)&deviceArray, arraySize * sizeof(float));

    // Measure the time before the data transfer
    auto start = std::chrono::high_resolution_clock::now();

    // Copy data from host to device
    cudaMemcpy(deviceArray, hostArray, arraySize * sizeof(float), cudaMemcpyHostToDevice);

    // Measure the time after the data transfer
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> duration = end - start;

    // Output the time taken
    std::cout << "Time taken for data transfer: " << duration.count() << " seconds" << std::endl;

    // Your CUDA code using deviceArray goes here...

    // Free allocated memory
    delete[] hostArray;
    cudaFree(deviceArray);

    return 0;
}
