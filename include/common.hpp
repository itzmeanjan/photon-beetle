#pragma once
#include "photon.hpp"
#include <cstddef>
#include <cstdint>

// Compile-time check for ensuring byte length is power of 2
constexpr inline static bool
check_po2(const size_t rate)
{
  return (rate & (rate - 1)) == 0;
}

// Absorbs N -bytes of input message into permutation state, see
// `HASH<RATE>(IV, D, c0)` algorithm defined in figure 3.6 of Photon-Beetle
// specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/photon-beetle-spec-final.pdf
template<const size_t RATE>
inline static void
absorb(uint8_t* const __restrict state, // 8x8 permutation state ( 256 -bit )
       const uint8_t* const __restrict msg, // input message to be absorbed
       const size_t mlen,                   // len(msg) | >= 0
       const uint8_t C                      // domain seperation constant
       ) requires(check_po2(RATE))
{
  const size_t full_blk = mlen / RATE;
  const size_t rm_bytes = mlen & (RATE - 1);

  for (size_t i = 0; i < full_blk; i++) {
    const size_t moff = i * RATE;

    photon::photon256(state);

#if defined __clang__
#pragma unroll
#elif defined __GNUG__
#pragma GCC ivdep
#endif
    for (size_t j = 0; j < RATE; j++) {
      const size_t soff = j << 1;

      const uint8_t y = (state[soff ^ 1] << 4) | (state[soff] & photon::LS4B);
      const uint8_t w = y ^ msg[moff ^ j];

      state[soff] = w & photon::LS4B;
      state[soff ^ 1] = w >> 4;
    }
  }

  if (rm_bytes > 0ul) {
    const size_t moff = full_blk * RATE;

    photon::photon256(state);

#if defined __clang__
#pragma unroll
#elif defined __GNUG__
#pragma GCC ivdep
#endif
    for (size_t j = 0; j < rm_bytes; j++) {
      const size_t soff = j << 1;

      const uint8_t y = (state[soff ^ 1] << 4) | (state[soff] & photon::LS4B);
      const uint8_t w = y ^ msg[moff ^ j];

      state[soff] = w & photon::LS4B;
      state[soff ^ 1] = w >> 4;
    }

    const size_t soff = rm_bytes << 1;

    const uint8_t y = (state[soff ^ 1] << 4) | (state[soff] & photon::LS4B);
    const uint8_t w = y ^ 0b1;

    state[soff] = w & photon::LS4B;
    state[soff ^ 1] = w >> 4;
  }

  state[63] ^= C << 1;
}

// Computes OUT -bytes tag, given 256 -bit permutation state, see
// `TAGτ (T0)` algorithm defined in figure 3.6 of Photon-Beetle specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/photon-beetle-spec-final.pdf
template<const size_t OUT>
inline static void
gen_tag(uint8_t* const __restrict state, // 8x8 permutation state ( 256 -bit )
        uint8_t* const __restrict tag    // OUT -bytes tag | OUT ∈ {16, 32}
        ) requires(check_po2(OUT))
{
  constexpr size_t CNT = OUT >> 4;

  for (size_t i = 0; i < CNT; i++) {
    const size_t toff = i << 4;

    photon::photon256(state);

#if defined __clang__
#pragma clang loop vectorize(enable)
#elif defined __GNUG__
#pragma GCC unroll 16
#pragma GCC ivdep
#endif
    for (size_t j = 0; j < 16; j++) {
      const size_t soff = j << 1;

      tag[toff ^ j] = (state[soff ^ 1] << 4) | (state[soff] & photon::LS4B);
    }
  }
}
