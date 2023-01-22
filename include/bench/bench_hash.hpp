#pragma once
#include "hash.hpp"
#include "utils.hpp"
#include <benchmark/benchmark.h>

// Benchmark Photon-Beetle-{Hash, AEAD} routines
namespace bench_photon_beetle {

// Benchmarks Photon-Beetle cryptographic hash function implementation for
// random input of length N (>=0) -bytes | N is provided when setting up
// benchmark
void
hash(benchmark::State& state)
{
  const size_t mlen = static_cast<size_t>(state.range(0));
  constexpr size_t dlen = 32ul;

  uint8_t* msg = static_cast<uint8_t*>(std::malloc(mlen));
  uint8_t* out = static_cast<uint8_t*>(std::malloc(dlen));

  random_data(msg, mlen);
  std::memset(out, 0, dlen);

  for (auto _ : state) {
    photon_beetle::hash(msg, mlen, out);

    benchmark::DoNotOptimize(out);
    benchmark::ClobberMemory();
  }

  state.SetBytesProcessed(static_cast<int64_t>(mlen * state.iterations()));

  std::free(msg);
  std::free(out);
}

}
