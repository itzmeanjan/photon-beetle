#pragma once
#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <random>
#include <sstream>

// Given a bytearray of length N, this function converts it to human readable
// hex string of length N << 1 | N >= 0
static inline const std::string
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
static inline void
random_data(uint8_t* const data, const size_t len)
{
  std::random_device rd;
  std::mt19937_64 gen(rd());
  std::uniform_int_distribution<uint8_t> dis;

  for (size_t i = 0; i < len; i++) {
    data[i] = dis(gen);
  }
}
