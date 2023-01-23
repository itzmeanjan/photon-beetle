#pragma once
#include "common.hpp"

// Photon-Beetle-{Hash, AEAD} function(s)
namespace photon_beetle {

// Photon-Beetle-Hash Digest is 32 -bytes wide, see section 3.3 of the
// specification
constexpr size_t DIGEST_LEN = 32ul;

// Photon-Beetle-Hash routine, which takes in N -bytes message & produces 32
// -bytes digest | N >= 0
//
// See `PHOTON-Beetle-Hash[r](M)` algorithm defined in figure 3.6 of
// Photon-Beetle specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/photon-beetle-spec-final.pdf
inline static void
hash(const uint8_t* const __restrict msg, // input message
     const size_t mlen,                   // len(msg) >= 0
     uint8_t* const __restrict digest     // 32 -bytes digest
)
{
  constexpr uint8_t C[2] = { 2, 1 };

  uint8_t state[64] = {};
  std::memset(state, 0, sizeof(state));

  if (mlen == 0ul) {
    state[63] ^= (1 << 1);
  } else {
    if (mlen <= 16ul) {
#if defined __clang__
#pragma unroll
#elif defined __GNUG__
#pragma GCC ivdep
#endif
      for (size_t i = 0; i < mlen; i++) {
        const size_t off = i << 1;

        state[off] = msg[i] & photon::LS4B;
        state[off ^ 1] = msg[i] >> 4;
      }

      constexpr uint8_t br0[2] = { 0, 0b1 };
      constexpr uint8_t br1[2] = { 2, 1 };

      const bool flg = mlen < 16ul;

      const size_t off = mlen << 1;
      state[off] = br0[flg];

      state[63] ^= (br1[flg] << 1);
    } else {
#if defined __clang__
#pragma unroll 16
#elif defined __GNUG__
#pragma GCC unroll 16
#pragma GCC ivdep
#endif
      for (size_t i = 0; i < 16; i++) {
        const size_t off = i << 1;

        state[off] = msg[i] & photon::LS4B;
        state[off ^ 1] = msg[i] >> 4;
      }

      const size_t rmlen = mlen - 16ul;
      const uint8_t c = C[(rmlen & 3ul) == 0];

      absorb<4ul>(state, msg + 16ul, rmlen, c);
    }
  }

  gen_tag<32ul>(state, digest);
}

// Photon-Beetle-Hash routine, which takes in N(>=0) -bytes message & computes
// 32 -bytes digest
//
// See `PHOTON-Beetle-Hash[r](M)` algorithm defined in figure 3.6 of
// Photon-Beetle specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/photon-beetle-spec-final.pdf
inline static void
_hash(const uint8_t* const __restrict msg, // input message
      const size_t mlen,                   // len(msg) >= 0
      uint8_t* const __restrict digest     // 32 -bytes digest
)
{
  uint8_t state[32]{};

  // when hashing empty message
  if (mlen == 0) [[unlikely]] {
    state[31] ^= (1 << 5);
    _gen_tag<32>(state, digest);

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
    _gen_tag<32>(state, digest);

    return;
  }

  // for all messages of length >16 -bytes
  std::memcpy(state, msg, 16);

  const size_t rmlen = mlen - 16;
  constexpr uint8_t C[]{ 2, 1 };
  const uint8_t c0 = C[(rmlen & 3ul) == 0ul];

  _absorb<4>(state, msg + 16, rmlen, c0);
  _gen_tag<32>(state, digest);
}

}
