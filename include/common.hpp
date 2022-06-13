#pragma once
#include "photon.hpp"
#include <bit>
#include <cmath>
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
#if defined __APPLE__
  const size_t log2RATE = std::log2(RATE);
#else
  constexpr size_t log2RATE = std::log2(RATE);
#endif

  const size_t full_blk = mlen >> log2RATE;
  const size_t rm_bytes = mlen & (RATE - 1);

  for (size_t i = 0; i < full_blk; i++) {
    const size_t moff = i << log2RATE;

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
    const size_t moff = full_blk << log2RATE;

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

  const uint8_t y = (state[63] << 4) | (state[62] & photon::LS4B);
  const uint8_t w = y ^ (C << 5);

  state[62] = w & photon::LS4B;
  state[63] = w >> 4;
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

// Shuffle RATE portion of 8x8 permutation state ( 256 -bit wide ), see
// section 3.1 of Photon-Beetle specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/photon-beetle-spec-final.pdf
template<const size_t RATE>
inline static void
shuffle(const uint8_t* const __restrict state,
        uint8_t* const __restrict shuffled) requires(check_po2(RATE))
{
  if constexpr (RATE == 4ul) {
    const uint16_t s1 = (static_cast<uint16_t>(state[3] & photon::LS4B) << 12) |
                        (static_cast<uint16_t>(state[2] & photon::LS4B) << 8) |
                        (static_cast<uint16_t>(state[1] & photon::LS4B) << 4) |
                        (static_cast<uint16_t>(state[0] & photon::LS4B) << 0);

    const uint16_t s1_prime = std::rotr(s1, 1);

    std::memcpy(shuffled, state + RATE, RATE);

    shuffled[4] = static_cast<uint8_t>(s1_prime >> 0) & photon::LS4B;
    shuffled[5] = static_cast<uint8_t>(s1_prime >> 4) & photon::LS4B;
    shuffled[6] = static_cast<uint8_t>(s1_prime >> 8) & photon::LS4B;
    shuffled[7] = static_cast<uint8_t>(s1_prime >> 12) & photon::LS4B;
  } else if constexpr (RATE == 16ul) {
    constexpr size_t CNT = RATE >> 1;

    uint64_t s1 = 0ul;

#if defined __clang__
#pragma unroll 8
#elif defined __GNUG__
#pragma GCC unroll 8
#pragma GCC ivdep
#endif
    for (size_t i = 0; i < CNT; i++) {
      const size_t soff = i << 1;
      const size_t shift = i << 3;

      const uint8_t w = (state[soff ^ 1] << 4) | (state[soff] & photon::LS4B);

      s1 |= static_cast<uint64_t>(w) << shift;
    }

    const uint64_t s1_prime = std::rotr(s1, 1);

    std::memcpy(shuffled, state + RATE, RATE);

#if defined __clang__
#pragma unroll 8
#elif defined __GNUG__
#pragma GCC unroll 8
#pragma GCC ivdep
#endif
    for (size_t i = 0; i < CNT; i++) {
      const size_t soff = RATE ^ (i << 1);
      const size_t shift = i << 3;

      const uint8_t w = static_cast<uint8_t>(s1_prime >> shift);

      shuffled[soff] = w & photon::LS4B;
      shuffled[soff ^ 1] = w >> 4;
    }
  }
}

// Linear function `ρ` used during authenticated encryption, as defined in
// section 3.1 of Photon-Beetle specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/photon-beetle-spec-final.pdf
template<const size_t RATE>
inline static void
rho(uint8_t* const __restrict state,
    const uint8_t* const __restrict txt,
    uint8_t* const __restrict enc,
    const size_t tlen)
{
  uint8_t tmp[RATE << 1];
  shuffle<RATE>(state, tmp);

#if defined __clang__
#pragma unroll
#elif defined __GNUG__
#pragma GCC ivdep
#endif
  for (size_t i = 0; i < tlen; i++) {
    const size_t soff = i << 1;
    const uint8_t w = (tmp[soff ^ 1] << 4) | (tmp[soff] & photon::LS4B);

    enc[i] = w ^ txt[i];
  }

#if defined __clang__
#pragma unroll
#elif defined __GNUG__
#pragma GCC ivdep
#endif
  for (size_t i = 0; i < tlen; i++) {
    const size_t soff = i << 1;

    const uint8_t y = (state[soff ^ 1] << 4) | (state[soff] & photon::LS4B);
    const uint8_t w = txt[i] ^ y;

    state[soff] = w & photon::LS4B;
    state[soff ^ 1] = w >> 4;
  }

  constexpr uint8_t br[2] = { 0, 1 };
  const size_t soff = tlen << 1;

  const uint8_t y = (state[soff ^ 1] << 4) | (state[soff] & photon::LS4B);
  const uint8_t w = y ^ br[tlen < RATE];

  state[soff] = w & photon::LS4B;
  state[soff ^ 1] = w >> 4;
}

// Linear function `ρ^-1` used during verified decryption ( which is just
// inverse of `ρ` ), as defined in section 3.1 of Photon-Beetle specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/photon-beetle-spec-final.pdf
template<const size_t RATE>
inline static void
inv_rho(uint8_t* const __restrict state,
        const uint8_t* const __restrict enc,
        uint8_t* const __restrict txt,
        const size_t tlen)
{
  uint8_t tmp[RATE << 1];
  shuffle<RATE>(state, tmp);

#if defined __clang__
#pragma unroll
#elif defined __GNUG__
#pragma GCC ivdep
#endif
  for (size_t i = 0; i < tlen; i++) {
    const size_t soff = i << 1;
    const uint8_t w = (tmp[soff ^ 1] << 4) | (tmp[soff] & photon::LS4B);

    txt[i] = w ^ enc[i];
  }

#if defined __clang__
#pragma unroll
#elif defined __GNUG__
#pragma GCC ivdep
#endif
  for (size_t i = 0; i < tlen; i++) {
    const size_t soff = i << 1;

    const uint8_t y = (state[soff ^ 1] << 4) | (state[soff] & photon::LS4B);
    const uint8_t w = txt[i] ^ y;

    state[soff] = w & photon::LS4B;
    state[soff ^ 1] = w >> 4;
  }

  constexpr uint8_t br[2] = { 0, 1 };
  const size_t soff = tlen << 1;

  const uint8_t y = (state[soff ^ 1] << 4) | (state[soff] & photon::LS4B);
  const uint8_t w = y ^ br[tlen < RATE];

  state[soff] = w & photon::LS4B;
  state[soff ^ 1] = w >> 4;
}
