#pragma once
#include <cstddef>
#include <cstdint>

namespace photon {

// Photon256 permutation has 12 rounds, see Photon-Bettle AEAD specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/photon-beetle-spec-final.pdf
constexpr size_t ROUNDS = 12ul;

// Photon256 permutation's round constants, taken from Photon-Bettle AEAD
// specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/photon-beetle-spec-final.pdf
constexpr uint8_t RC[96] = {
  1,  0,  2,  6,  14, 15, 13, 9,  3,  2,  0, 4,  12, 13, 15, 11, 7,  6,  4,  0,
  8,  9,  11, 15, 14, 15, 13, 9,  1,  0,  2, 6,  13, 12, 14, 10, 2,  3,  1,  5,
  11, 10, 8,  12, 4,  5,  7,  3,  6,  7,  5, 1,  9,  8,  10, 14, 12, 13, 15, 11,
  3,  2,  0,  4,  9,  8,  10, 14, 6,  7,  5, 1,  2,  3,  1,  5,  13, 12, 14, 10,
  5,  4,  6,  2,  10, 11, 9,  13, 10, 11, 9, 13, 5,  4,  6,  2
};

// Compile-time evaluation to check round index is valid
static inline constexpr bool
check_r(const size_t r)
{
  return r < ROUNDS;
}

// Add fixed constants to the cells of first column of 8x8 permutation state
template<const size_t r>
inline static void
add_constant(
  uint8_t* const __restrict state // 8x8 permutation state ( 256 -bits )
  ) requires(check_r(r))
{
  constexpr size_t off = r << 3;

#if defined __clang__
#pragma unroll 8
#elif defined __GNUG__
#pragma GCC unroll 8
#endif
  for (size_t i = 0; i < 8; i++) {
    state[i << 3] ^= RC[off ^ i];
  }
}

}
