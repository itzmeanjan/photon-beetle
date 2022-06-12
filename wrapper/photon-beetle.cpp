#include "hash.hpp"

// Thin C wrapper on top of underlying C++ implementation of Photon-Beetle hash
// function, which can be used for producing shared library object with C-ABI &
// used from other languages such as Rust, Python

// Function prototype
extern "C"
{
  void photon_beetle_hash(const uint8_t* const __restrict,
                          const size_t,
                          uint8_t* const __restrict);
}

// Function implementation
extern "C"
{
  // Given N (>=0) -bytes input message, this routines computes 32 -bytes output
  // digest, using Photon-Beetle hashing algorithm
  void photon_beetle_hash(const uint8_t* const __restrict in,
                          const size_t ilen,
                          uint8_t* const __restrict out)
  {
    photon_beetle::hash(in, ilen, out);
  }
}
