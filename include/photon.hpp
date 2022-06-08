#pragma once
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace photon {

// Photon256 permutation has 12 rounds, see Photon-Bettle AEAD specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/photon-beetle-spec-final.pdf
constexpr size_t ROUNDS = 12ul;

// Photon256 permutation's round constants, see Photon-Bettle AEAD specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/photon-beetle-spec-final.pdf
constexpr uint8_t RC[96] = {
  1,  0,  2,  6,  14, 15, 13, 9,  3,  2,  0, 4,  12, 13, 15, 11, 7,  6,  4,  0,
  8,  9,  11, 15, 14, 15, 13, 9,  1,  0,  2, 6,  13, 12, 14, 10, 2,  3,  1,  5,
  11, 10, 8,  12, 4,  5,  7,  3,  6,  7,  5, 1,  9,  8,  10, 14, 12, 13, 15, 11,
  3,  2,  0,  4,  9,  8,  10, 14, 6,  7,  5, 1,  2,  3,  1,  5,  13, 12, 14, 10,
  5,  4,  6,  2,  10, 11, 9,  13, 10, 11, 9, 13, 5,  4,  6,  2
};

// 4 -bit S-box applied to each cell of 8x8 permutation state matrix, see
// Photon-Bettle AEAD specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/photon-beetle-spec-final.pdf
constexpr uint8_t SBOX[16] = { 0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD,
                               0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2 };

// Compile-time evaluation to check round index is valid
static inline constexpr bool
check_r(const size_t r)
{
  return r < ROUNDS;
}

// Add fixed constants to the cells of first column of 8x8 permutation state,
// see figure 2.1 of Photon-Bettle AEAD specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/photon-beetle-spec-final.pdf
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

// Applies 4 -bit S-box to each cell of 8x8 permutation state, see figure 2.1 of
// Photon-Bettle AEAD specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/photon-beetle-spec-final.pdf
inline static void
subcells(uint8_t* const __restrict state // 8x8 permutation state ( 256 -bits )
)
{
  for (size_t i = 0; i < 64; i++) {
    state[i] = SBOX[state[i]];
  }
}

// Rotates position of the cells in each row by row index places, see figure 2.1
// of Photon-Bettle AEAD specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/photon-beetle-spec-final.pdf
inline static void
shift_rows(
  uint8_t* const __restrict state // 8x8 permutation state ( 256 -bits )
)
{
  uint8_t s_prime[64];

  for (size_t i = 0; i < 8; i++) {
    const size_t off = i << 3;

    for (size_t j = 0; j < 8; j++) {
      s_prime[off ^ j] = state[off ^ ((j + i) & 7ul)];
    }
  }

  std::memcpy(state, s_prime, sizeof(s_prime));
}

}
