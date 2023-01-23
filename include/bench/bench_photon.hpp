#pragma once
#include "photon.hpp"
#include "utils.hpp"
#include <benchmark/benchmark.h>

// Benchmark Photon-Beetle-{Hash, AEAD} routines
namespace bench_photon_beetle {

// Benchmarks Photon256 permutation routine
void
permute(benchmark::State& state)
{
  uint8_t pstate[64];

  // generate initial random permutation state
  random_data(pstate, 64);

  for (auto _ : state) {
    photon::photon256(pstate);

    benchmark::DoNotOptimize(pstate);
    benchmark::ClobberMemory();
  }

  state.SetBytesProcessed(state.iterations() * (sizeof(pstate) / 2));
}

// Benchmarks Photon256 permutation routine
void
_permute(benchmark::State& state)
{
  uint8_t pstate[32];

  // generate initial random permutation state
  random_data(pstate, 32);

  for (auto _ : state) {
    photon::_photon256(pstate);

    benchmark::DoNotOptimize(pstate);
    benchmark::ClobberMemory();
  }

  state.SetBytesProcessed(state.iterations() * sizeof(pstate));
}

}
