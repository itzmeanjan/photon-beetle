#pragma once
#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <sstream>

// Given a bytearray of length N, this function converts it to human readable
// hex string of length N << 1
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
