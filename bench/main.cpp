#include "bench/bench_photon_beetle.hpp"

// registering Photon256 permutation routine for benchmark
BENCHMARK(bench_photon_beetle::permute);
BENCHMARK(bench_photon_beetle::_permute);

// registering Photon-Beetle-Hash function for benchmark
BENCHMARK(bench_photon_beetle::hash)->Arg(64);
BENCHMARK(bench_photon_beetle::hash)->Arg(128);
BENCHMARK(bench_photon_beetle::hash)->Arg(256);
BENCHMARK(bench_photon_beetle::hash)->Arg(512);
BENCHMARK(bench_photon_beetle::hash)->Arg(1024);
BENCHMARK(bench_photon_beetle::hash)->Arg(2048);
BENCHMARK(bench_photon_beetle::hash)->Arg(4096);

// registering Photon-Beetle-AEAD[32, 128] encrypt/ decrypt function(s) for
// benchmark
BENCHMARK(bench_photon_beetle::aead_encrypt<4>)->Args({ 32, 64 });
BENCHMARK(bench_photon_beetle::aead_decrypt<4>)->Args({ 32, 64 });
BENCHMARK(bench_photon_beetle::aead_encrypt<4>)->Args({ 32, 128 });
BENCHMARK(bench_photon_beetle::aead_decrypt<4>)->Args({ 32, 128 });
BENCHMARK(bench_photon_beetle::aead_encrypt<4>)->Args({ 32, 256 });
BENCHMARK(bench_photon_beetle::aead_decrypt<4>)->Args({ 32, 256 });
BENCHMARK(bench_photon_beetle::aead_encrypt<4>)->Args({ 32, 512 });
BENCHMARK(bench_photon_beetle::aead_decrypt<4>)->Args({ 32, 512 });
BENCHMARK(bench_photon_beetle::aead_encrypt<4>)->Args({ 32, 1024 });
BENCHMARK(bench_photon_beetle::aead_decrypt<4>)->Args({ 32, 1024 });
BENCHMARK(bench_photon_beetle::aead_encrypt<4>)->Args({ 32, 2048 });
BENCHMARK(bench_photon_beetle::aead_decrypt<4>)->Args({ 32, 2048 });
BENCHMARK(bench_photon_beetle::aead_encrypt<4>)->Args({ 32, 4096 });
BENCHMARK(bench_photon_beetle::aead_decrypt<4>)->Args({ 32, 4096 });

BENCHMARK(bench_photon_beetle::aead_encrypt<16>)->Args({ 32, 64 });
BENCHMARK(bench_photon_beetle::aead_decrypt<16>)->Args({ 32, 64 });
BENCHMARK(bench_photon_beetle::aead_encrypt<16>)->Args({ 32, 128 });
BENCHMARK(bench_photon_beetle::aead_decrypt<16>)->Args({ 32, 128 });
BENCHMARK(bench_photon_beetle::aead_encrypt<16>)->Args({ 32, 256 });
BENCHMARK(bench_photon_beetle::aead_decrypt<16>)->Args({ 32, 256 });
BENCHMARK(bench_photon_beetle::aead_encrypt<16>)->Args({ 32, 512 });
BENCHMARK(bench_photon_beetle::aead_decrypt<16>)->Args({ 32, 512 });
BENCHMARK(bench_photon_beetle::aead_encrypt<16>)->Args({ 32, 1024 });
BENCHMARK(bench_photon_beetle::aead_decrypt<16>)->Args({ 32, 1024 });
BENCHMARK(bench_photon_beetle::aead_encrypt<16>)->Args({ 32, 2048 });
BENCHMARK(bench_photon_beetle::aead_decrypt<16>)->Args({ 32, 2048 });
BENCHMARK(bench_photon_beetle::aead_encrypt<16>)->Args({ 32, 4096 });
BENCHMARK(bench_photon_beetle::aead_decrypt<16>)->Args({ 32, 4096 });

// main function to drive execution of benchmark
BENCHMARK_MAIN();
