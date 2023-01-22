#pragma once
#include "utils.hpp"
#include <bit>
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
constexpr uint64_t RC[]{ 1,  0,  2,  6,  14, 15, 13, 9,  3,  2,  0,  4,  12, 13,
                         15, 11, 7,  6,  4,  0,  8,  9,  11, 15, 14, 15, 13, 9,
                         1,  0,  2,  6,  13, 12, 14, 10, 2,  3,  1,  5,  11, 10,
                         8,  12, 4,  5,  7,  3,  6,  7,  5,  1,  9,  8,  10, 14,
                         12, 13, 15, 11, 3,  2,  0,  4,  9,  8,  10, 14, 6,  7,
                         5,  1,  2,  3,  1,  5,  13, 12, 14, 10, 5,  4,  6,  2,
                         10, 11, 9,  13, 10, 11, 9,  13, 5,  4,  6,  2 };

// Photon256 permutation's round constants, see Photon-Beetle specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/photon-beetle-spec-final.pdf
constexpr uint32_t _RC[]{
  1,  0,  2,  6,  14, 15, 13, 9,  3,  2,  0, 4,  12, 13, 15, 11, 7,  6,  4,  0,
  8,  9,  11, 15, 14, 15, 13, 9,  1,  0,  2, 6,  13, 12, 14, 10, 2,  3,  1,  5,
  11, 10, 8,  12, 4,  5,  7,  3,  6,  7,  5, 1,  9,  8,  10, 14, 12, 13, 15, 11,
  3,  2,  0,  4,  9,  8,  10, 14, 6,  7,  5, 1,  2,  3,  1,  5,  13, 12, 14, 10,
  5,  4,  6,  2,  10, 11, 9,  13, 10, 11, 9, 13, 5,  4,  6,  2
};

// 4 -bit S-box applied to each cell of 8x8 permutation state matrix, see
// Photon-Beetle specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/photon-beetle-spec-final.pdf
constexpr uint8_t SBOX[]{ 0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD,
                          0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2 };

// Compute 8 -bit S-box from 4 -bit S-box
inline static consteval uint8_t
get_8bit_sbox(const uint8_t a, const uint8_t b)
{
  return (SBOX[a & LS4B] << 4) | (SBOX[b & LS4B]);
}

// Compile-time compute 8 -bit S-box table
constexpr uint8_t SBOX_8BIT[]{
  get_8bit_sbox(0, 0),   get_8bit_sbox(0, 1),   get_8bit_sbox(0, 2),
  get_8bit_sbox(0, 3),   get_8bit_sbox(0, 4),   get_8bit_sbox(0, 5),
  get_8bit_sbox(0, 6),   get_8bit_sbox(0, 7),   get_8bit_sbox(0, 8),
  get_8bit_sbox(0, 9),   get_8bit_sbox(0, 10),  get_8bit_sbox(0, 11),
  get_8bit_sbox(0, 12),  get_8bit_sbox(0, 13),  get_8bit_sbox(0, 14),
  get_8bit_sbox(0, 15),  get_8bit_sbox(1, 0),   get_8bit_sbox(1, 1),
  get_8bit_sbox(1, 2),   get_8bit_sbox(1, 3),   get_8bit_sbox(1, 4),
  get_8bit_sbox(1, 5),   get_8bit_sbox(1, 6),   get_8bit_sbox(1, 7),
  get_8bit_sbox(1, 8),   get_8bit_sbox(1, 9),   get_8bit_sbox(1, 10),
  get_8bit_sbox(1, 11),  get_8bit_sbox(1, 12),  get_8bit_sbox(1, 13),
  get_8bit_sbox(1, 14),  get_8bit_sbox(1, 15),  get_8bit_sbox(2, 0),
  get_8bit_sbox(2, 1),   get_8bit_sbox(2, 2),   get_8bit_sbox(2, 3),
  get_8bit_sbox(2, 4),   get_8bit_sbox(2, 5),   get_8bit_sbox(2, 6),
  get_8bit_sbox(2, 7),   get_8bit_sbox(2, 8),   get_8bit_sbox(2, 9),
  get_8bit_sbox(2, 10),  get_8bit_sbox(2, 11),  get_8bit_sbox(2, 12),
  get_8bit_sbox(2, 13),  get_8bit_sbox(2, 14),  get_8bit_sbox(2, 15),
  get_8bit_sbox(3, 0),   get_8bit_sbox(3, 1),   get_8bit_sbox(3, 2),
  get_8bit_sbox(3, 3),   get_8bit_sbox(3, 4),   get_8bit_sbox(3, 5),
  get_8bit_sbox(3, 6),   get_8bit_sbox(3, 7),   get_8bit_sbox(3, 8),
  get_8bit_sbox(3, 9),   get_8bit_sbox(3, 10),  get_8bit_sbox(3, 11),
  get_8bit_sbox(3, 12),  get_8bit_sbox(3, 13),  get_8bit_sbox(3, 14),
  get_8bit_sbox(3, 15),  get_8bit_sbox(4, 0),   get_8bit_sbox(4, 1),
  get_8bit_sbox(4, 2),   get_8bit_sbox(4, 3),   get_8bit_sbox(4, 4),
  get_8bit_sbox(4, 5),   get_8bit_sbox(4, 6),   get_8bit_sbox(4, 7),
  get_8bit_sbox(4, 8),   get_8bit_sbox(4, 9),   get_8bit_sbox(4, 10),
  get_8bit_sbox(4, 11),  get_8bit_sbox(4, 12),  get_8bit_sbox(4, 13),
  get_8bit_sbox(4, 14),  get_8bit_sbox(4, 15),  get_8bit_sbox(5, 0),
  get_8bit_sbox(5, 1),   get_8bit_sbox(5, 2),   get_8bit_sbox(5, 3),
  get_8bit_sbox(5, 4),   get_8bit_sbox(5, 5),   get_8bit_sbox(5, 6),
  get_8bit_sbox(5, 7),   get_8bit_sbox(5, 8),   get_8bit_sbox(5, 9),
  get_8bit_sbox(5, 10),  get_8bit_sbox(5, 11),  get_8bit_sbox(5, 12),
  get_8bit_sbox(5, 13),  get_8bit_sbox(5, 14),  get_8bit_sbox(5, 15),
  get_8bit_sbox(6, 0),   get_8bit_sbox(6, 1),   get_8bit_sbox(6, 2),
  get_8bit_sbox(6, 3),   get_8bit_sbox(6, 4),   get_8bit_sbox(6, 5),
  get_8bit_sbox(6, 6),   get_8bit_sbox(6, 7),   get_8bit_sbox(6, 8),
  get_8bit_sbox(6, 9),   get_8bit_sbox(6, 10),  get_8bit_sbox(6, 11),
  get_8bit_sbox(6, 12),  get_8bit_sbox(6, 13),  get_8bit_sbox(6, 14),
  get_8bit_sbox(6, 15),  get_8bit_sbox(7, 0),   get_8bit_sbox(7, 1),
  get_8bit_sbox(7, 2),   get_8bit_sbox(7, 3),   get_8bit_sbox(7, 4),
  get_8bit_sbox(7, 5),   get_8bit_sbox(7, 6),   get_8bit_sbox(7, 7),
  get_8bit_sbox(7, 8),   get_8bit_sbox(7, 9),   get_8bit_sbox(7, 10),
  get_8bit_sbox(7, 11),  get_8bit_sbox(7, 12),  get_8bit_sbox(7, 13),
  get_8bit_sbox(7, 14),  get_8bit_sbox(7, 15),  get_8bit_sbox(8, 0),
  get_8bit_sbox(8, 1),   get_8bit_sbox(8, 2),   get_8bit_sbox(8, 3),
  get_8bit_sbox(8, 4),   get_8bit_sbox(8, 5),   get_8bit_sbox(8, 6),
  get_8bit_sbox(8, 7),   get_8bit_sbox(8, 8),   get_8bit_sbox(8, 9),
  get_8bit_sbox(8, 10),  get_8bit_sbox(8, 11),  get_8bit_sbox(8, 12),
  get_8bit_sbox(8, 13),  get_8bit_sbox(8, 14),  get_8bit_sbox(8, 15),
  get_8bit_sbox(9, 0),   get_8bit_sbox(9, 1),   get_8bit_sbox(9, 2),
  get_8bit_sbox(9, 3),   get_8bit_sbox(9, 4),   get_8bit_sbox(9, 5),
  get_8bit_sbox(9, 6),   get_8bit_sbox(9, 7),   get_8bit_sbox(9, 8),
  get_8bit_sbox(9, 9),   get_8bit_sbox(9, 10),  get_8bit_sbox(9, 11),
  get_8bit_sbox(9, 12),  get_8bit_sbox(9, 13),  get_8bit_sbox(9, 14),
  get_8bit_sbox(9, 15),  get_8bit_sbox(10, 0),  get_8bit_sbox(10, 1),
  get_8bit_sbox(10, 2),  get_8bit_sbox(10, 3),  get_8bit_sbox(10, 4),
  get_8bit_sbox(10, 5),  get_8bit_sbox(10, 6),  get_8bit_sbox(10, 7),
  get_8bit_sbox(10, 8),  get_8bit_sbox(10, 9),  get_8bit_sbox(10, 10),
  get_8bit_sbox(10, 11), get_8bit_sbox(10, 12), get_8bit_sbox(10, 13),
  get_8bit_sbox(10, 14), get_8bit_sbox(10, 15), get_8bit_sbox(11, 0),
  get_8bit_sbox(11, 1),  get_8bit_sbox(11, 2),  get_8bit_sbox(11, 3),
  get_8bit_sbox(11, 4),  get_8bit_sbox(11, 5),  get_8bit_sbox(11, 6),
  get_8bit_sbox(11, 7),  get_8bit_sbox(11, 8),  get_8bit_sbox(11, 9),
  get_8bit_sbox(11, 10), get_8bit_sbox(11, 11), get_8bit_sbox(11, 12),
  get_8bit_sbox(11, 13), get_8bit_sbox(11, 14), get_8bit_sbox(11, 15),
  get_8bit_sbox(12, 0),  get_8bit_sbox(12, 1),  get_8bit_sbox(12, 2),
  get_8bit_sbox(12, 3),  get_8bit_sbox(12, 4),  get_8bit_sbox(12, 5),
  get_8bit_sbox(12, 6),  get_8bit_sbox(12, 7),  get_8bit_sbox(12, 8),
  get_8bit_sbox(12, 9),  get_8bit_sbox(12, 10), get_8bit_sbox(12, 11),
  get_8bit_sbox(12, 12), get_8bit_sbox(12, 13), get_8bit_sbox(12, 14),
  get_8bit_sbox(12, 15), get_8bit_sbox(13, 0),  get_8bit_sbox(13, 1),
  get_8bit_sbox(13, 2),  get_8bit_sbox(13, 3),  get_8bit_sbox(13, 4),
  get_8bit_sbox(13, 5),  get_8bit_sbox(13, 6),  get_8bit_sbox(13, 7),
  get_8bit_sbox(13, 8),  get_8bit_sbox(13, 9),  get_8bit_sbox(13, 10),
  get_8bit_sbox(13, 11), get_8bit_sbox(13, 12), get_8bit_sbox(13, 13),
  get_8bit_sbox(13, 14), get_8bit_sbox(13, 15), get_8bit_sbox(14, 0),
  get_8bit_sbox(14, 1),  get_8bit_sbox(14, 2),  get_8bit_sbox(14, 3),
  get_8bit_sbox(14, 4),  get_8bit_sbox(14, 5),  get_8bit_sbox(14, 6),
  get_8bit_sbox(14, 7),  get_8bit_sbox(14, 8),  get_8bit_sbox(14, 9),
  get_8bit_sbox(14, 10), get_8bit_sbox(14, 11), get_8bit_sbox(14, 12),
  get_8bit_sbox(14, 13), get_8bit_sbox(14, 14), get_8bit_sbox(14, 15),
  get_8bit_sbox(15, 0),  get_8bit_sbox(15, 1),  get_8bit_sbox(15, 2),
  get_8bit_sbox(15, 3),  get_8bit_sbox(15, 4),  get_8bit_sbox(15, 5),
  get_8bit_sbox(15, 6),  get_8bit_sbox(15, 7),  get_8bit_sbox(15, 8),
  get_8bit_sbox(15, 9),  get_8bit_sbox(15, 10), get_8bit_sbox(15, 11),
  get_8bit_sbox(15, 12), get_8bit_sbox(15, 13), get_8bit_sbox(15, 14),
  get_8bit_sbox(15, 15)
};

// M^8 = Serial[2, 4, 2, 11, 2, 8, 5, 6] ^ 8 | Serial[...] is defined in
// section 1.1 of Photon-Beetle specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/photon-beetle-spec-final.pdf
constexpr uint8_t M8[]{ 2,  4, 2,  11, 2,  8,  5,  6,  12, 9,  8,  13, 7,
                        7,  5, 2,  4,  4,  13, 13, 9,  4,  13, 9,  1,  6,
                        5,  1, 12, 13, 15, 14, 15, 12, 9,  13, 14, 5,  14,
                        13, 9, 14, 5,  15, 4,  12, 9,  6,  12, 2,  2,  10,
                        3,  1, 1,  14, 15, 1,  13, 10, 5,  10, 2,  3 };

// Modular multiplication in GF(2^4) with irreducible polynomial x^4 + x + 1
inline static constexpr uint8_t
gf16_mult(const uint8_t a, const uint8_t b)
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

// Compile-time compute table, holding result of multiplication of
// a, b ∈ GF(2^4)
constexpr uint8_t GF16_MUL_TAB[]{
  gf16_mult(0, 0),   gf16_mult(0, 1),   gf16_mult(0, 2),   gf16_mult(0, 3),
  gf16_mult(0, 4),   gf16_mult(0, 5),   gf16_mult(0, 6),   gf16_mult(0, 7),
  gf16_mult(0, 8),   gf16_mult(0, 9),   gf16_mult(0, 10),  gf16_mult(0, 11),
  gf16_mult(0, 12),  gf16_mult(0, 13),  gf16_mult(0, 14),  gf16_mult(0, 15),
  gf16_mult(1, 0),   gf16_mult(1, 1),   gf16_mult(1, 2),   gf16_mult(1, 3),
  gf16_mult(1, 4),   gf16_mult(1, 5),   gf16_mult(1, 6),   gf16_mult(1, 7),
  gf16_mult(1, 8),   gf16_mult(1, 9),   gf16_mult(1, 10),  gf16_mult(1, 11),
  gf16_mult(1, 12),  gf16_mult(1, 13),  gf16_mult(1, 14),  gf16_mult(1, 15),
  gf16_mult(2, 0),   gf16_mult(2, 1),   gf16_mult(2, 2),   gf16_mult(2, 3),
  gf16_mult(2, 4),   gf16_mult(2, 5),   gf16_mult(2, 6),   gf16_mult(2, 7),
  gf16_mult(2, 8),   gf16_mult(2, 9),   gf16_mult(2, 10),  gf16_mult(2, 11),
  gf16_mult(2, 12),  gf16_mult(2, 13),  gf16_mult(2, 14),  gf16_mult(2, 15),
  gf16_mult(3, 0),   gf16_mult(3, 1),   gf16_mult(3, 2),   gf16_mult(3, 3),
  gf16_mult(3, 4),   gf16_mult(3, 5),   gf16_mult(3, 6),   gf16_mult(3, 7),
  gf16_mult(3, 8),   gf16_mult(3, 9),   gf16_mult(3, 10),  gf16_mult(3, 11),
  gf16_mult(3, 12),  gf16_mult(3, 13),  gf16_mult(3, 14),  gf16_mult(3, 15),
  gf16_mult(4, 0),   gf16_mult(4, 1),   gf16_mult(4, 2),   gf16_mult(4, 3),
  gf16_mult(4, 4),   gf16_mult(4, 5),   gf16_mult(4, 6),   gf16_mult(4, 7),
  gf16_mult(4, 8),   gf16_mult(4, 9),   gf16_mult(4, 10),  gf16_mult(4, 11),
  gf16_mult(4, 12),  gf16_mult(4, 13),  gf16_mult(4, 14),  gf16_mult(4, 15),
  gf16_mult(5, 0),   gf16_mult(5, 1),   gf16_mult(5, 2),   gf16_mult(5, 3),
  gf16_mult(5, 4),   gf16_mult(5, 5),   gf16_mult(5, 6),   gf16_mult(5, 7),
  gf16_mult(5, 8),   gf16_mult(5, 9),   gf16_mult(5, 10),  gf16_mult(5, 11),
  gf16_mult(5, 12),  gf16_mult(5, 13),  gf16_mult(5, 14),  gf16_mult(5, 15),
  gf16_mult(6, 0),   gf16_mult(6, 1),   gf16_mult(6, 2),   gf16_mult(6, 3),
  gf16_mult(6, 4),   gf16_mult(6, 5),   gf16_mult(6, 6),   gf16_mult(6, 7),
  gf16_mult(6, 8),   gf16_mult(6, 9),   gf16_mult(6, 10),  gf16_mult(6, 11),
  gf16_mult(6, 12),  gf16_mult(6, 13),  gf16_mult(6, 14),  gf16_mult(6, 15),
  gf16_mult(7, 0),   gf16_mult(7, 1),   gf16_mult(7, 2),   gf16_mult(7, 3),
  gf16_mult(7, 4),   gf16_mult(7, 5),   gf16_mult(7, 6),   gf16_mult(7, 7),
  gf16_mult(7, 8),   gf16_mult(7, 9),   gf16_mult(7, 10),  gf16_mult(7, 11),
  gf16_mult(7, 12),  gf16_mult(7, 13),  gf16_mult(7, 14),  gf16_mult(7, 15),
  gf16_mult(8, 0),   gf16_mult(8, 1),   gf16_mult(8, 2),   gf16_mult(8, 3),
  gf16_mult(8, 4),   gf16_mult(8, 5),   gf16_mult(8, 6),   gf16_mult(8, 7),
  gf16_mult(8, 8),   gf16_mult(8, 9),   gf16_mult(8, 10),  gf16_mult(8, 11),
  gf16_mult(8, 12),  gf16_mult(8, 13),  gf16_mult(8, 14),  gf16_mult(8, 15),
  gf16_mult(9, 0),   gf16_mult(9, 1),   gf16_mult(9, 2),   gf16_mult(9, 3),
  gf16_mult(9, 4),   gf16_mult(9, 5),   gf16_mult(9, 6),   gf16_mult(9, 7),
  gf16_mult(9, 8),   gf16_mult(9, 9),   gf16_mult(9, 10),  gf16_mult(9, 11),
  gf16_mult(9, 12),  gf16_mult(9, 13),  gf16_mult(9, 14),  gf16_mult(9, 15),
  gf16_mult(10, 0),  gf16_mult(10, 1),  gf16_mult(10, 2),  gf16_mult(10, 3),
  gf16_mult(10, 4),  gf16_mult(10, 5),  gf16_mult(10, 6),  gf16_mult(10, 7),
  gf16_mult(10, 8),  gf16_mult(10, 9),  gf16_mult(10, 10), gf16_mult(10, 11),
  gf16_mult(10, 12), gf16_mult(10, 13), gf16_mult(10, 14), gf16_mult(10, 15),
  gf16_mult(11, 0),  gf16_mult(11, 1),  gf16_mult(11, 2),  gf16_mult(11, 3),
  gf16_mult(11, 4),  gf16_mult(11, 5),  gf16_mult(11, 6),  gf16_mult(11, 7),
  gf16_mult(11, 8),  gf16_mult(11, 9),  gf16_mult(11, 10), gf16_mult(11, 11),
  gf16_mult(11, 12), gf16_mult(11, 13), gf16_mult(11, 14), gf16_mult(11, 15),
  gf16_mult(12, 0),  gf16_mult(12, 1),  gf16_mult(12, 2),  gf16_mult(12, 3),
  gf16_mult(12, 4),  gf16_mult(12, 5),  gf16_mult(12, 6),  gf16_mult(12, 7),
  gf16_mult(12, 8),  gf16_mult(12, 9),  gf16_mult(12, 10), gf16_mult(12, 11),
  gf16_mult(12, 12), gf16_mult(12, 13), gf16_mult(12, 14), gf16_mult(12, 15),
  gf16_mult(13, 0),  gf16_mult(13, 1),  gf16_mult(13, 2),  gf16_mult(13, 3),
  gf16_mult(13, 4),  gf16_mult(13, 5),  gf16_mult(13, 6),  gf16_mult(13, 7),
  gf16_mult(13, 8),  gf16_mult(13, 9),  gf16_mult(13, 10), gf16_mult(13, 11),
  gf16_mult(13, 12), gf16_mult(13, 13), gf16_mult(13, 14), gf16_mult(13, 15),
  gf16_mult(14, 0),  gf16_mult(14, 1),  gf16_mult(14, 2),  gf16_mult(14, 3),
  gf16_mult(14, 4),  gf16_mult(14, 5),  gf16_mult(14, 6),  gf16_mult(14, 7),
  gf16_mult(14, 8),  gf16_mult(14, 9),  gf16_mult(14, 10), gf16_mult(14, 11),
  gf16_mult(14, 12), gf16_mult(14, 13), gf16_mult(14, 14), gf16_mult(14, 15),
  gf16_mult(15, 0),  gf16_mult(15, 1),  gf16_mult(15, 2),  gf16_mult(15, 3),
  gf16_mult(15, 4),  gf16_mult(15, 5),  gf16_mult(15, 6),  gf16_mult(15, 7),
  gf16_mult(15, 8),  gf16_mult(15, 9),  gf16_mult(15, 10), gf16_mult(15, 11),
  gf16_mult(15, 12), gf16_mult(15, 13), gf16_mult(15, 14), gf16_mult(15, 15)
};

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

  uint64_t tmp[8];
  std::memcpy(tmp, state, sizeof(tmp));

  // swap byte order on non little-endian platform
  if constexpr (std::endian::native != std::endian::little) {

#if defined __clang__
    // Following
    // https://clang.llvm.org/docs/LanguageExtensions.html#extensions-for-loop-hint-optimizations

#pragma clang loop unroll(enable)
#pragma clang loop vectorize(enable)
#elif defined __GNUG__
    // Following
    // https://gcc.gnu.org/onlinedocs/gcc/Loop-Specific-Pragmas.html#Loop-Specific-Pragmas

#pragma GCC ivdep
#pragma GCC unroll 8
#endif
    for (size_t i = 0; i < 8; i++) {
      tmp[i] = bswap64(tmp[i]);
    }
  }

#if defined __clang__
  // Following
  // https://clang.llvm.org/docs/LanguageExtensions.html#extensions-for-loop-hint-optimizations

#pragma clang loop unroll(enable)
#pragma clang loop vectorize(enable)
#elif defined __GNUG__
  // Following
  // https://gcc.gnu.org/onlinedocs/gcc/Loop-Specific-Pragmas.html#Loop-Specific-Pragmas

#pragma GCC ivdep
#pragma GCC unroll 8
#endif
  for (size_t i = 0; i < 8; i++) {
    tmp[i] ^= RC[off + i];
  }

  std::memcpy(state, tmp, sizeof(tmp));
}

// Add fixed constants to the cells of first column of 8x4 permutation state,
// see figure 2.1 of Photon-Beetle specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/photon-beetle-spec-final.pdf
inline static void
_add_constant(uint8_t* const __restrict state, // 8x4 permutation state
              const size_t r                   // round index | >= 0 && < 12
)
{
  const size_t off = r << 3;

  uint32_t tmp[8];
  std::memcpy(tmp, state, sizeof(tmp));

  // swap byte order on non little-endian platform
  if constexpr (std::endian::native != std::endian::little) {

#if defined __clang__
    // Following
    // https://clang.llvm.org/docs/LanguageExtensions.html#extensions-for-loop-hint-optimizations

#pragma clang loop unroll(enable)
#pragma clang loop vectorize(enable)
#elif defined __GNUG__
    // Following
    // https://gcc.gnu.org/onlinedocs/gcc/Loop-Specific-Pragmas.html#Loop-Specific-Pragmas

#pragma GCC ivdep
#pragma GCC unroll 8
#endif
    for (size_t i = 0; i < 8; i++) {
      tmp[i] = bswap32(tmp[i]);
    }
  }

#if defined __clang__
  // Following
  // https://clang.llvm.org/docs/LanguageExtensions.html#extensions-for-loop-hint-optimizations

#pragma clang loop unroll(enable)
#pragma clang loop vectorize(enable)
#elif defined __GNUG__
  // Following
  // https://gcc.gnu.org/onlinedocs/gcc/Loop-Specific-Pragmas.html#Loop-Specific-Pragmas

#pragma GCC ivdep
#pragma GCC unroll 8
#endif
  for (size_t i = 0; i < 8; i++) {
    tmp[i] ^= _RC[off + i];
  }

  std::memcpy(state, tmp, sizeof(tmp));
}

// Applies 4 -bit S-box to each cell of 8x8 permutation state, see figure 2.1 of
// Photon-Beetle specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/photon-beetle-spec-final.pdf
inline static void
subcells(uint8_t* const __restrict state // 8x8 permutation state ( 256 -bits )
)
{
#if defined __clang__
  // Following
  // https://clang.llvm.org/docs/LanguageExtensions.html#extensions-for-loop-hint-optimizations

#pragma clang loop unroll(enable)
#elif defined __GNUG__
  // Following
  // https://gcc.gnu.org/onlinedocs/gcc/Loop-Specific-Pragmas.html#Loop-Specific-Pragmas

#pragma GCC ivdep
#pragma GCC unroll 16
#endif
  for (size_t i = 0; i < 64; i++) {
    state[i] = SBOX[state[i] & LS4B];
  }
}

// Applies 8 -bit S-box to each cell of 8x4 permutation state, see figure 2.1 of
// Photon-Beetle specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/photon-beetle-spec-final.pdf
inline static void
_subcells(uint8_t* const __restrict state)
{
#if defined __clang__
  // Following
  // https://clang.llvm.org/docs/LanguageExtensions.html#extensions-for-loop-hint-optimizations

#pragma clang loop unroll(enable)
#elif defined __GNUG__
  // Following
  // https://gcc.gnu.org/onlinedocs/gcc/Loop-Specific-Pragmas.html#Loop-Specific-Pragmas

#pragma GCC ivdep
#pragma GCC unroll 16
#endif
  for (size_t i = 0; i < 32; i++) {
    state[i] = SBOX_8BIT[state[i]];
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
  uint64_t tmp[8];
  std::memcpy(tmp, state, sizeof(tmp));

#if defined __clang__
  // Following
  // https://clang.llvm.org/docs/LanguageExtensions.html#extensions-for-loop-hint-optimizations

#pragma clang loop unroll(enable)
#pragma clang loop vectorize(enable)
#elif defined __GNUG__
  // Following
  // https://gcc.gnu.org/onlinedocs/gcc/Loop-Specific-Pragmas.html#Loop-Specific-Pragmas

#pragma GCC ivdep
#pragma GCC unroll 8
#endif
  for (size_t i = 0; i < 8; i++) {
    if constexpr (std::endian::native == std::endian::little) {
      tmp[i] = std::rotr(tmp[i], i * 8);
    } else {
      tmp[i] = std::rotl(tmp[i], i * 8);
    }
  }

  std::memcpy(state, tmp, sizeof(tmp));
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
  uint8_t s_prime[64]{};

#if defined __clang__
  // Following
  // https://clang.llvm.org/docs/LanguageExtensions.html#extensions-for-loop-hint-optimizations

#pragma clang loop unroll(enable)
#elif defined __GNUG__
  // Following
  // https://gcc.gnu.org/onlinedocs/gcc/Loop-Specific-Pragmas.html#Loop-Specific-Pragmas

#pragma GCC ivdep
#pragma GCC unroll 8
#endif
  for (size_t i = 0; i < 8; i++) {
    const size_t off = i * 8;

#if defined __clang__
    // Following
    // https://clang.llvm.org/docs/LanguageExtensions.html#extensions-for-loop-hint-optimizations

#pragma clang loop unroll(enable)
#elif defined __GNUG__
    // Following
    // https://gcc.gnu.org/onlinedocs/gcc/Loop-Specific-Pragmas.html#Loop-Specific-Pragmas

#pragma GCC ivdep
#pragma GCC unroll 8
#endif
    for (size_t k = 0; k < 8; k++) {
#if defined __clang__
      // Following
      // https://clang.llvm.org/docs/LanguageExtensions.html#extensions-for-loop-hint-optimizations

#pragma clang loop unroll(enable)
#elif defined __GNUG__
      // Following
      // https://gcc.gnu.org/onlinedocs/gcc/Loop-Specific-Pragmas.html#Loop-Specific-Pragmas

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
