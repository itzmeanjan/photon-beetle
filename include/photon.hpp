#pragma once
#include <cstddef>
#include <cstdint>
#include <cstring>

// Photon256 permutation, used in Photon-Beetle-{AEAD, Hash}
namespace photon {

// Photon256 permutation has 12 rounds, see Photon-Beetle specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/photon-beetle-spec-final.pdf
constexpr size_t ROUNDS = 12ul;

// Bitmask used for extracting least significant 4 -bits ( 1 nibble ) of a byte
constexpr uint8_t LS4B = 0x0f;

// Irreducible polynomial (x^4 + x + 1) = 19 = 0x13, used for matrix
// multiplication in MixColumnSerial step of Photon256 permutation
//
// Note, only least significant 4 -bits are taken for irreducible polynomial
// because each cell of Photon256 permutation matrix is 4 -bits wide, which are
// kept of lower ( read LSB ) 4 -bits of a byte
constexpr uint8_t IRP = 0b00010011 & LS4B;

// Photon256 permutation's round constants, see Photon-Beetle specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/photon-beetle-spec-final.pdf
constexpr uint8_t RC[96] = {
  1,  0,  2,  6,  14, 15, 13, 9,  3,  2,  0, 4,  12, 13, 15, 11, 7,  6,  4,  0,
  8,  9,  11, 15, 14, 15, 13, 9,  1,  0,  2, 6,  13, 12, 14, 10, 2,  3,  1,  5,
  11, 10, 8,  12, 4,  5,  7,  3,  6,  7,  5, 1,  9,  8,  10, 14, 12, 13, 15, 11,
  3,  2,  0,  4,  9,  8,  10, 14, 6,  7,  5, 1,  2,  3,  1,  5,  13, 12, 14, 10,
  5,  4,  6,  2,  10, 11, 9,  13, 10, 11, 9, 13, 5,  4,  6,  2
};

// 4 -bit S-box applied to each cell of 8x8 permutation state matrix, see
// Photon-Beetle specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/photon-beetle-spec-final.pdf
constexpr uint8_t SBOX[16] = { 0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD,
                               0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2 };

// M^8 = Serial[2, 4, 2, 11, 2, 8, 5, 6] ^ 8 | Serial[...] is defined in
// section 1.1 of Photon-Beetle specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/photon-beetle-spec-final.pdf
constexpr uint8_t M8[64] = { 2,  4, 2,  11, 2,  8,  5,  6,  12, 9,  8,  13, 7,
                             7,  5, 2,  4,  4,  13, 13, 9,  4,  13, 9,  1,  6,
                             5,  1, 12, 13, 15, 14, 15, 12, 9,  13, 14, 5,  14,
                             13, 9, 14, 5,  15, 4,  12, 9,  6,  12, 2,  2,  10,
                             3,  1, 1,  14, 15, 1,  13, 10, 5,  10, 2,  3 };

// Add fixed constants to the cells of first column of 8x8 permutation state,
// see figure 2.1 of Photon-Beetle specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/photon-beetle-spec-final.pdf
inline static void
add_constant(
  uint8_t* const __restrict state, // 8x8 permutation state ( 256 -bits )
  const size_t r                   // round index | >= 0 && < 12
)
{
  const size_t off = r << 3;

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
// Photon-Beetle specification
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
// of Photon-Beetle specification
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

// Modular multiplication in GF(2^4) with irreducible polynomial x^4 + x + 1
inline static uint8_t
gf16_mult(const uint8_t a, const uint8_t b)
{
  constexpr uint8_t br0[2] = { 0, IRP };

  uint8_t x = a;
  uint8_t res = 0;

  for (size_t i = 0; i < 4; i++) {
    const uint8_t br1[2] = { 0, x };

    const bool flg0 = (b >> i) & 0b1;
    const bool flg1 = (x >> 3) & 0b1;

    res ^= br1[flg0];

    x <<= 1;
    x ^= br0[flg1];
  }

  return res & LS4B;
}

// Linearly mixes all the columns independently using a serial matrix
// multiplication on GF(2^4), see figure 2.1 of Photon-Beetle AEAD
// specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/photon-beetle-spec-final.pdf
inline static void
mix_column_serial(
  uint8_t* const __restrict state // 8x8 permutation state ( 256 -bits )
)
{
  for (size_t i = 0; i < 8; i++) {
    uint8_t row[8] = { 0 };

    for (size_t j = 0; j < 8; j++) {
      for (size_t k = 0; k < 8; k++) {
        row[j] ^= gf16_mult(M8[(i << 3) + k], state[(k << 3) + j]);
      }
    }

    std::memcpy(state + (i << 3), row, sizeof(row));
  }
}

// Photon256 permutation composed of 12 rounds, see chapter 2 of Photon-Beetle
// specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/photon-beetle-spec-final.pdf
inline static void
photon256(uint8_t* const __restrict state // 8x8 permutation state ( 256 -bits )
)
{
  for (size_t i = 0; i < ROUNDS; i++) {
    add_constant(state, i);
    subcells(state);
    shift_rows(state);
    mix_column_serial(state);
  }
}

}
