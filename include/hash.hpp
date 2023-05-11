#pragma once
#include "common.hpp"

// Photon-Beetle-{Hash, AEAD} function(s)
namespace photon_beetle {

static_assert(__SIZEOF_INT128__ == 16, "128 -bit unsigned integer is needed !");
using uint128_t = unsigned __int128;

// Photon-Beetle-Hash Digest is 32 -bytes wide, see section 3.3 of the
// specification
constexpr size_t DIGEST_LEN = 32ul;

// Photon-Beetle-Hash routine, which takes in N(>=0) -bytes message & computes
// 32 -bytes digest
//
// See `PHOTON-Beetle-Hash[r](M)` algorithm defined in figure 3.6 of
// Photon-Beetle specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/photon-beetle-spec-final.pdf
inline void
hash(const uint8_t* const __restrict msg, // input message
     const size_t mlen,                   // len(msg) >= 0
     uint8_t* const __restrict digest     // 32 -bytes digest
)
{
  uint8_t state[32]{};

  // when hashing empty message
  if (mlen == 0) [[unlikely]] {
    state[31] ^= (1 << 5);
    photon_common::gen_tag<32>(state, digest);

    return;
  }

  // when hashing fairly small message
  if (mlen <= 16) [[likely]] {
    const bool flg = mlen < 16;

    if constexpr (std::endian::native == std::endian::little) {
      const size_t bit_off = (flg * mlen) * 8;
      uint128_t mword = static_cast<uint128_t>(1) << bit_off;
      std::memcpy(&mword, msg, mlen);
      std::memcpy(state, &mword, sizeof(mword));
    } else {
      const size_t bit_off = (15 - (flg * mlen)) * 8;
      uint128_t mword = static_cast<uint128_t>(1) << bit_off;
      std::memcpy(&mword, msg, mlen);
      std::memcpy(state, &mword, sizeof(mword));
    }

    constexpr uint8_t br[]{ 2, 1 };
    const uint8_t c0 = br[flg];

    state[31] ^= (c0 << 5);
    photon_common::gen_tag<32>(state, digest);

    return;
  }

  // for all messages of length >16 -bytes
  std::memcpy(state, msg, 16);

  const size_t rmlen = mlen - 16;
  constexpr uint8_t C[]{ 2, 1 };
  const uint8_t c0 = C[(rmlen & 3ul) == 0ul];

  photon_common::absorb<4>(state, msg + 16, rmlen, c0);
  photon_common::gen_tag<32>(state, digest);
}

}
