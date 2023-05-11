#pragma once
#include "utils.hpp"
#include <array>
#include <bit>
#include <cstdint>
#include <cstring>

#if defined __SSSE3__
#include <tmmintrin.h>
#endif

// Photon256 permutation, used in Photon-Beetle-{AEAD, Hash}
//
// Photon-Beetle Specification lives at
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/photon-beetle-spec-final.pdf
//
// Find Clang loop optimization guide at
// https://clang.llvm.org/docs/LanguageExtensions.html#extensions-for-loop-hint-optimizations
//
// While GCC loop optimization guide lives at
// https://gcc.gnu.org/onlinedocs/gcc/Loop-Specific-Pragmas.html#Loop-Specific-Pragmas
namespace photon {

// Photon256 permutation has 12 rounds, see figure 2.1 of the specification
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

// Photon256 permutation's round constants, see figure 2.1 of the specification
constexpr std::array<uint32_t, 96> RC{
  1,  0,  2,  6,  14, 15, 13, 9,  3,  2,  0, 4,  12, 13, 15, 11, 7,  6,  4,  0,
  8,  9,  11, 15, 14, 15, 13, 9,  1,  0,  2, 6,  13, 12, 14, 10, 2,  3,  1,  5,
  11, 10, 8,  12, 4,  5,  7,  3,  6,  7,  5, 1,  9,  8,  10, 14, 12, 13, 15, 11,
  3,  2,  0,  4,  9,  8,  10, 14, 6,  7,  5, 1,  2,  3,  1,  5,  13, 12, 14, 10,
  5,  4,  6,  2,  10, 11, 9,  13, 10, 11, 9, 13, 5,  4,  6,  2
};

// Compile-time compute 8 -bit S-box table from 4 -bit S-box table
inline static constexpr std::array<uint8_t, 256>
compute_8bit_sbox()
{
  // 4 -bit S-box table
  constexpr std::array<uint8_t, 16> SBOX{ 0xC, 0x5, 0x6, 0xB, 0x9, 0x0,
                                          0xA, 0xD, 0x3, 0xE, 0xF, 0x8,
                                          0x4, 0x7, 0x1, 0x2 };
  std::array<uint8_t, 256> res;

  for (size_t i = 0; i < 16; i++) {
    for (size_t j = 0; j < 16; j++) {
      res[i * 16 + j] = (SBOX[i & LS4B] << 4) | SBOX[j & LS4B];
    }
  }

  return res;
}

// Modular multiplication in GF(2^4) with irreducible polynomial x^4 + x + 1
inline static constexpr uint8_t
gf16_mul(const uint8_t a, const uint8_t b)
{
  constexpr uint8_t br0[]{ 0, IRP };

  uint8_t x = a;
  uint8_t res = 0;

  for (size_t i = 0; i < 4; i++) {
    const uint8_t br1[]{ 0, x };

    const bool flg0 = (b >> i) & 0b1;
    const bool flg1 = (x >> 3) & 0b1;

    res ^= br1[flg0];

    x <<= 1;
    x ^= br0[flg1];
  }

  return res & LS4B;
}

// Compile-time compute GF(2^4) multiplication look-up table
inline static constexpr std::array<uint8_t, 256>
compute_gf16_mul_table()
{
  std::array<uint8_t, 256> res;

  for (size_t i = 0; i < 16; i++) {
    for (size_t j = 0; j < 16; j++) {
      res[i * 16 + j] = gf16_mul(i, j);
    }
  }

  return res;
}

// Compile-time computed 8 -bit S-box look-up table
constexpr std::array<uint8_t, 256> SBOX = compute_8bit_sbox();

// Compile-time computed GF(2^4) multiplication look-up table. If you want to
// multiply a with b s.t. a, b ∈ GF(2^4), look up what's the value stored at
// index (a*16 + b) of this array.
constexpr std::array<uint8_t, 256> GF16_MUL_TAB = compute_gf16_mul_table();

// Given a 8x8 matrix M s.t. its elements ∈ GF(2^4), this compile time
// executable routine is used for squaring M i.e. returning M' <- M x M s.t. M'
// is a 8x8 matrix over GF(2^4), meaning the matrix multiplication is performed
// over GF(2^4), using pre-computed multiplication lookup table.
constexpr std::array<uint8_t, 64>
gf16_matrix_square(std::array<uint8_t, 64> mat)
{
  std::array<uint8_t, 64> res{};

#if defined __clang__
#pragma clang loop unroll(enable)
#elif defined __GNUG__
#pragma GCC ivdep
#pragma GCC unroll 8
#endif
  for (size_t i = 0; i < 8; i++) {

#if defined __clang__
#pragma clang loop unroll(enable)
#elif defined __GNUG__
#pragma GCC ivdep
#pragma GCC unroll 8
#endif
    for (size_t k = 0; k < 8; k++) {
#if defined __clang__
#pragma clang loop unroll(enable)
#elif defined __GNUG__
#pragma GCC ivdep
#pragma GCC unroll 8
#endif
      for (size_t j = 0; j < 8; j++) {
        const uint8_t idx = (mat[i * 8 + k] << 4) | (mat[(k * 8) + j] & LS4B);
        res[i * 8 + j] ^= GF16_MUL_TAB[idx];
      }
    }
  }

  return res;
}

// Given a serial matrix M <- Serial[2, 4, 2, 11, 2, 8, 5, 6] as it's defined in
// section 1.1 of the specification, this compile-time executable routine is
// used for raising M to its 8th power, by repeated squaring, returning M^8.
constexpr std::array<uint8_t, 64>
compute_M8()
{
  std::array<uint8_t, 64> M{ 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0,  0, 0, 0, 0,
                             0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0,  1, 0, 0, 0,
                             0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0,  0, 0, 1, 0,
                             0, 0, 0, 0, 0, 0, 0, 1, 2, 4, 2, 11, 2, 8, 5, 6 };

  auto M2 = gf16_matrix_square(M);
  auto M4 = gf16_matrix_square(M2);
  auto M8 = gf16_matrix_square(M4);

  return M8;
}

// Compile-time computed M^8 = Serial[2, 4, 2, 11, 2, 8, 5, 6] ^ 8 | Serial[...]
// is defined in section 1.1 of the specification.
constexpr std::array<uint8_t, 64> M8 = compute_M8();

// Add fixed constants to the cells of first column of 8x4 permutation state,
// see figure 2.1 of the specification
inline static void
add_constant(uint8_t* const __restrict state, // 8x4 permutation state
             const size_t r                   // round index | >= 0 && < 12
)
{
  const size_t off = r << 3;

  uint32_t tmp[8];
  std::memcpy(tmp, state, sizeof(tmp));

  // swap byte order on non little-endian platform
  if constexpr (std::endian::native != std::endian::little) {

#if defined __clang__
#pragma clang loop unroll(enable)
#pragma clang loop vectorize(enable)
#elif defined __GNUG__
#pragma GCC ivdep
#pragma GCC unroll 8
#endif
    for (size_t i = 0; i < 8; i++) {
      tmp[i] = photon_utils::bswap32(tmp[i]);
    }
  }

#if defined __clang__
#pragma clang loop unroll(enable)
#pragma clang loop vectorize(enable)
#elif defined __GNUG__
#pragma GCC ivdep
#pragma GCC unroll 8
#endif
  for (size_t i = 0; i < 8; i++) {
    tmp[i] ^= RC[off + i];
  }

  std::memcpy(state, tmp, sizeof(tmp));
}

// Applies 8 -bit S-box to each cell of 8x4 permutation state, see figure 2.1 of
// the specification
inline static void
subcells(uint8_t* const __restrict state)
{
#if defined __clang__
#pragma clang loop unroll(enable)
#elif defined __GNUG__
#pragma GCC ivdep
#pragma GCC unroll 32
#endif
  for (size_t i = 0; i < 32; i++) {
    state[i] = SBOX[state[i]];
  }
}

// Rotates position of the cells ( of 8x4 permutation state matrix ) in each row
// by row index places, see figure 2.1 of the specification
inline static void
shift_rows(uint8_t* const __restrict state)
{
  uint32_t tmp[8];
  std::memcpy(tmp, state, sizeof(tmp));

#if defined __clang__
#pragma clang loop unroll(enable)
#pragma clang loop vectorize(enable)
#elif defined __GNUG__
#pragma GCC ivdep
#pragma GCC unroll 8
#endif
  for (size_t i = 0; i < 8; i++) {
    if constexpr (std::endian::native == std::endian::little) {
      tmp[i] = std::rotr(tmp[i], i * 4);
    } else {
      tmp[i] = std::rotl(tmp[i], i * 4);
    }
  }

  std::memcpy(state, tmp, sizeof(tmp));
}

// Linearly mixes all the columns ( of permutation state matrix of dimension 8x8
// i.e. each cell of matrix holds its significant bits using lower 4 bits )
// independently using a serial matrix multiplication over GF(2^4), see
// figure 2.1 of the specification
inline static void
mix_column_serial_inner(
  uint8_t* const __restrict state // 8x8 permutation state ( 256 -bits )
)
{
  uint8_t s_prime[64]{};

#if defined __clang__
#pragma clang loop unroll(enable)
#elif defined __GNUG__
#pragma GCC ivdep
#pragma GCC unroll 8
#endif
  for (size_t i = 0; i < 8; i++) {
    const size_t off = i * 8;

#if defined __clang__
#pragma clang loop unroll(enable)
#elif defined __GNUG__
#pragma GCC ivdep
#pragma GCC unroll 8
#endif
    for (size_t k = 0; k < 8; k++) {
#if defined __clang__
#pragma clang loop unroll(enable)
#elif defined __GNUG__
#pragma GCC ivdep
#pragma GCC unroll 8
#endif
      for (size_t j = 0; j < 8; j++) {
        const uint8_t idx = (M8[off + k] << 4) | (state[(k * 8) + j] & LS4B);
        s_prime[off + j] ^= GF16_MUL_TAB[idx];
      }
    }
  }

  std::memcpy(state, s_prime, sizeof(s_prime));
}

// Linearly mixes all the columns ( of permutation state matrix of dimension 8x4
// ) independently using a serial matrix multiplication over GF(2^4), see
// figure 2.1 of the specification
inline static void
mix_column_serial(uint8_t* const __restrict state)
{
  uint8_t tmp[64];

#if (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__) && defined __SSSE3__

  constexpr uint32_t mask0 = 0x0f0f0f0fu;
  constexpr uint32_t mask1 = mask0 << 4;
  constexpr uint64_t mask2 = 0x0703060205010400ul;

#if defined __clang__
#pragma clang loop unroll(enable)
#elif defined __GNUG__
#pragma GCC ivdep
#pragma GCC unroll 8
#endif
  for (size_t i = 0; i < 8; i++) {
    uint32_t row;
    std::memcpy(&row, state + i * sizeof(row), sizeof(row));

    const auto t0 = row & mask0;
    const auto t1 = (row & mask1) >> 4;

    const uint64_t t2 = ((uint64_t)t1 << 32) | (uint64_t)t0;
    const uint64_t t3 = (uint64_t)_mm_shuffle_pi8((__m64)t2, (__m64)mask2);

    std::memcpy(tmp + i * sizeof(t3), &t3, sizeof(t3));
  }

#else

#if defined __clang__
#pragma clang loop unroll(enable)
#pragma clang loop vectorize(enable)
#elif defined __GNUG__
#pragma GCC ivdep
#pragma GCC unroll 32
#endif
  for (size_t i = 0; i < 32; i++) {
    tmp[2 * i] = state[i] & LS4B;
    tmp[2 * i + 1] = state[i] >> 4;
  }

#endif

  mix_column_serial_inner(tmp);

#if defined __clang__
#pragma clang loop unroll(enable)
#pragma clang loop vectorize(enable)
#elif defined __GNUG__
#pragma GCC ivdep
#pragma GCC unroll 32
#endif
  for (size_t i = 0; i < 32; i++) {
    state[i] = (tmp[2 * i + 1] << 4) | tmp[2 * i];
  }
}

// Photon256 permutation composed of 12 rounds, applied on a state matrix of
// dimension 8x4, see chapter 2 ( on page 2 ) of the specification
inline void
photon256(uint8_t* const __restrict state)
{
  for (size_t i = 0; i < ROUNDS; i++) {
    add_constant(state, i);
    subcells(state);
    shift_rows(state);
    mix_column_serial(state);
  }
}

}
