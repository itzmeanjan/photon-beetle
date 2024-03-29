#pragma once
#include "photon.hpp"
#include <benchmark/benchmark.h>

// Benchmark Photon-Beetle-{Hash, AEAD} routines
namespace bench_photon_beetle {

// Benchmarks Photon256 permutation routine
inline void
permute(benchmark::State& state)
{
  uint8_t pstate[32];

  // generate initial random permutation state
  photon_utils::random_data(pstate, sizeof(pstate));

  for (auto _ : state) {
    photon::photon256(pstate);

    benchmark::DoNotOptimize(pstate);
    benchmark::ClobberMemory();
  }

  state.SetBytesProcessed(state.iterations() * sizeof(pstate));
}

}
