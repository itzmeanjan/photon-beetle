#include "bench_hash.hpp"

// registering Photon-Beetle-Hash function for benchmark
BENCHMARK(bench_photon_beetle::hash)->Arg(64);
BENCHMARK(bench_photon_beetle::hash)->Arg(128);
BENCHMARK(bench_photon_beetle::hash)->Arg(256);
BENCHMARK(bench_photon_beetle::hash)->Arg(512);
BENCHMARK(bench_photon_beetle::hash)->Arg(1024);
BENCHMARK(bench_photon_beetle::hash)->Arg(2048);
BENCHMARK(bench_photon_beetle::hash)->Arg(4096);

// main function to drive execution of benchmark
BENCHMARK_MAIN();
