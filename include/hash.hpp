#pragma once
#include "common.hpp"

// Photon-Beetle-{Hash, AEAD} function(s)
namespace photon_beetle {

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

}
