#pragma once
#include "aead.hpp"
#include <benchmark/benchmark.h>
#include <cassert>

// Benchmark Photon-Beetle-{Hash, AEAD} routines
namespace bench_photon_beetle {

// Benchmarks Photon-Beetle-AEAD[32, 128] instance's encrypt routine on CPU
// based systems
template<const size_t R>
void
aead_encrypt(benchmark::State& state)
{
  const size_t dlen = static_cast<size_t>(state.range(0));
  const size_t mlen = static_cast<size_t>(state.range(1));

  uint8_t* key = static_cast<uint8_t*>(std::malloc(16));
  uint8_t* nonce = static_cast<uint8_t*>(std::malloc(16));
  uint8_t* tag = static_cast<uint8_t*>(std::malloc(16));
  uint8_t* data = static_cast<uint8_t*>(std::malloc(dlen));
  uint8_t* txt = static_cast<uint8_t*>(std::malloc(mlen));
  uint8_t* enc = static_cast<uint8_t*>(std::malloc(mlen));
  uint8_t* dec = static_cast<uint8_t*>(std::malloc(mlen));

  photon_utils::random_data(key, 16);
  photon_utils::random_data(nonce, 16);
  photon_utils::random_data(data, dlen);
  photon_utils::random_data(txt, mlen);

  for (auto _ : state) {
    photon_beetle::encrypt<R>(key, nonce, data, dlen, txt, enc, mlen, tag);

    benchmark::DoNotOptimize(key);
    benchmark::DoNotOptimize(nonce);
    benchmark::DoNotOptimize(data);
    benchmark::DoNotOptimize(dlen);
    benchmark::DoNotOptimize(txt);
    benchmark::DoNotOptimize(enc);
    benchmark::DoNotOptimize(mlen);
    benchmark::DoNotOptimize(tag);
    benchmark::ClobberMemory();
  }

  // --- test correctness ---
  bool f0 = false;
  f0 = photon_beetle::decrypt<R>(key, nonce, tag, data, dlen, enc, dec, mlen);

  assert(f0);

  bool f1 = false;
  for (size_t i = 0; i < mlen; i++) {
    f1 |= static_cast<bool>(txt[i] ^ dec[i]);
  }

  assert(!f1);
  // --- test correctness ---

  const size_t per_itr = mlen + dlen;
  state.SetBytesProcessed(static_cast<int64_t>(per_itr * state.iterations()));

  std::free(key);
  std::free(nonce);
  std::free(tag);
  std::free(data);
  std::free(txt);
  std::free(enc);
  std::free(dec);
}

// Benchmarks Photon-Beetle-AEAD[32, 128] instance's decrypt routine on CPU
// based systems
template<const size_t R>
void
aead_decrypt(benchmark::State& state)
{
  const size_t dlen = static_cast<size_t>(state.range(0));
  const size_t mlen = static_cast<size_t>(state.range(1));

  uint8_t* key = static_cast<uint8_t*>(std::malloc(16));
  uint8_t* nonce = static_cast<uint8_t*>(std::malloc(16));
  uint8_t* tag = static_cast<uint8_t*>(std::malloc(16));
  uint8_t* data = static_cast<uint8_t*>(std::malloc(dlen));
  uint8_t* txt = static_cast<uint8_t*>(std::malloc(mlen));
  uint8_t* enc = static_cast<uint8_t*>(std::malloc(mlen));
  uint8_t* dec = static_cast<uint8_t*>(std::malloc(mlen));

  photon_utils::random_data(key, 16);
  photon_utils::random_data(nonce, 16);
  photon_utils::random_data(data, dlen);
  photon_utils::random_data(txt, mlen);

  photon_beetle::encrypt<R>(key, nonce, data, dlen, txt, enc, mlen, tag);

  for (auto _ : state) {
    bool f0 = false;
    f0 = photon_beetle::decrypt<R>(key, nonce, tag, data, dlen, enc, dec, mlen);
    assert(f0);

    benchmark::DoNotOptimize(key);
    benchmark::DoNotOptimize(nonce);
    benchmark::DoNotOptimize(tag);
    benchmark::DoNotOptimize(data);
    benchmark::DoNotOptimize(dlen);
    benchmark::DoNotOptimize(enc);
    benchmark::DoNotOptimize(dec);
    benchmark::DoNotOptimize(mlen);
    benchmark::ClobberMemory();
  }

  // --- test correctness ---
  bool f = false;
  for (size_t i = 0; i < mlen; i++) {
    f |= static_cast<bool>(txt[i] ^ dec[i]);
  }

  assert(!f);
  // --- test correctness ---

  const size_t per_itr = mlen + dlen;
  state.SetBytesProcessed(static_cast<int64_t>(per_itr * state.iterations()));

  std::free(key);
  std::free(nonce);
  std::free(tag);
  std::free(data);
  std::free(txt);
  std::free(enc);
  std::free(dec);
}

}
