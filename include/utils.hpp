#pragma once
#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <random>
#include <sstream>

// Utility functions used in Photon-Beetle-{Hash, AEAD}
namespace photon_utils {

// Given a 32 -bit unsigned integer word, this routine swaps byte order and
// returns byte swapped 32 -bit word.
//
// Taken from
// https://github.com/itzmeanjan/xoodyak/blob/89b3427/include/utils.hpp#L14-L28
inline constexpr uint32_t
bswap32(const uint32_t a)
{
#if defined __GNUG__
  return __builtin_bswap32(a);
#else
  return ((a & 0x000000ffu) << 24) | ((a & 0x0000ff00u) << 0x08) |
         ((a & 0x00ff0000u) >> 0x08) | ((a & 0xff000000u) >> 24);
#endif
}

// Given a bytearray of length N, this function converts it to human readable
// hex string of length N << 1 | N >= 0
inline const std::string
to_hex(const uint8_t* const bytes, const size_t len)
{
  std::stringstream ss;
  ss << std::hex;

  for (size_t i = 0; i < len; i++) {
    ss << std::setw(2) << std::setfill('0') << static_cast<uint32_t>(bytes[i]);
  }

  return ss.str();
}

// Generates N -many random bytes | N >= 0
inline void
random_data(uint8_t* const data, const size_t len)
{
  std::random_device rd;
  std::mt19937_64 gen(rd());
  std::uniform_int_distribution<uint8_t> dis;

  for (size_t i = 0; i < len; i++) {
    data[i] = dis(gen);
  }
}

}
