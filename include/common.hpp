#pragma once
#include "photon.hpp"
#include <algorithm>
#include <bit>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>

using uint128_t = unsigned __int128;

// Compile-time check for ensuring that RATE ∈ {4, 16}
inline static consteval bool
check_rate(const size_t rate)
{
  return (rate == 4) || (rate == 16);
}

// Compile-time check for ensuring that OUT ∈ {16, 32}
inline static consteval bool
check_out(const size_t out)
{
  return (out == 16) || (out == 32);
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
       )
  requires(check_rate(RATE))
{
  constexpr uint8_t br[]{ 0, 1 };

  for (size_t i = 0; i < mlen; i += RATE) {
    // effective byte length i.e. # -of bytes to be absorbed in this iteration
    const size_t elen = std::min(RATE, mlen - i);

    photon::photon256(state);

#if defined __clang__
#pragma unroll
#elif defined __GNUG__
#pragma GCC ivdep
#endif
    for (size_t j = 0; j < elen; j++) {
      const size_t soff = j << 1;

      const uint8_t y = (state[soff ^ 1] << 4) | (state[soff] & photon::LS4B);
      const uint8_t w = y ^ msg[i ^ j];

      state[soff] = w & photon::LS4B;
      state[soff ^ 1] = w >> 4;
    }
  }

  const size_t rm_bytes = mlen & (RATE - 1);
  const size_t soff = rm_bytes << 1;

  const uint8_t y = (state[soff ^ 1] << 4) | (state[soff] & photon::LS4B);
  const uint8_t w = y ^ br[rm_bytes > 0];

  state[soff] = w & photon::LS4B;
  state[soff ^ 1] = w >> 4;

  {
    const uint8_t y = (state[63] << 4) | (state[62] & photon::LS4B);
    const uint8_t w = y ^ (C << 5);

    state[62] = w & photon::LS4B;
    state[63] = w >> 4;
  }
}

// Absorbs N (>=0) -bytes of input message into permutation state, see
// `HASH<RATE>(IV, D, c0)` algorithm defined in figure 3.6 of Photon-Beetle
// specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/photon-beetle-spec-final.pdf
template<const size_t RATE>
inline static void
_absorb(uint8_t* const __restrict state,     // 8x4 permutation state
        const uint8_t* const __restrict msg, // input message to be absorbed
        const size_t mlen,                   // len(msg) | >= 0
        const uint8_t C                      // domain seperation constant
        )
  requires(check_rate(RATE))
{
  if constexpr (RATE == 4) {
    static_assert(RATE == 4, "Rate portion of state must be 32 -bit wide");

    const size_t full_blk_cnt = mlen / RATE;
    const size_t full_blk_bytes = full_blk_cnt * RATE;

    size_t off = 0;
    while (off < full_blk_bytes) {
      photon::_photon256(state);

      uint32_t rate;
      std::memcpy(&rate, state, RATE);

      uint32_t mword;
      std::memcpy(&mword, msg + off, RATE);

      const auto nrate = rate ^ mword;
      std::memcpy(state, &nrate, RATE);

      off += RATE;
    }

    const size_t rm_bytes = mlen - off;
    if (rm_bytes > 0) {
      photon::_photon256(state);

      if constexpr (std::endian::native == std::endian::little) {
        uint32_t rate;
        std::memcpy(&rate, state, RATE);

        uint32_t mword = 1u << (rm_bytes * 8);
        std::memcpy(&mword, msg + off, rm_bytes);

        const auto nrate = rate ^ mword;
        std::memcpy(state, &nrate, RATE);
      } else {
        uint32_t rate;
        std::memcpy(&rate, state, RATE);

        uint32_t mword = 16777216u >> (rm_bytes * 8);
        std::memcpy(&mword, msg + off, rm_bytes);

        const auto nrate = rate ^ mword;
        std::memcpy(state, &nrate, RATE);
      }
    }
  } else {
    static_assert(RATE == 16, "Rate portion of state must be 128 -bit wide");

    const size_t full_blk_cnt = mlen / RATE;
    const size_t full_blk_bytes = full_blk_cnt * RATE;

    size_t off = 0;
    while (off < full_blk_bytes) {
      photon::_photon256(state);

      uint128_t rate;
      std::memcpy(&rate, state, RATE);

      uint128_t mword;
      std::memcpy(&mword, msg + off, RATE);

      const auto nrate = rate ^ mword;
      std::memcpy(state, &nrate, RATE);

      off += RATE;
    }

    const size_t rm_bytes = mlen - off;
    if (rm_bytes > 0) {
      photon::_photon256(state);

      if constexpr (std::endian::native == std::endian::little) {
        uint128_t rate;
        std::memcpy(&rate, state, RATE);

        uint128_t mword = static_cast<uint128_t>(1) << (rm_bytes * 8);
        std::memcpy(&mword, msg + off, rm_bytes);

        const auto nrate = rate ^ mword;
        std::memcpy(state, &nrate, RATE);
      } else {
        uint128_t rate;
        std::memcpy(&rate, state, RATE);

        uint128_t mword = static_cast<uint128_t>(1) << ((15 - rm_bytes) * 8);
        std::memcpy(&mword, msg + off, rm_bytes);

        const auto nrate = rate ^ mword;
        std::memcpy(state, &nrate, RATE);
      }
    }
  }

  // add domain seperation constant
  state[31] ^= (C << 5);
}

// Computes OUT -bytes tag, given 256 -bit permutation state, see
// `TAGτ (T0)` algorithm defined in figure 3.6 of Photon-Beetle specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/photon-beetle-spec-final.pdf
template<const size_t OUT>
inline static void
gen_tag(uint8_t* const __restrict state, // 8x8 permutation state ( 256 -bit )
        uint8_t* const __restrict tag    // OUT -bytes tag | OUT ∈ {16, 32}
        )
  requires(check_out(OUT))
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

// Computes OUT -bytes tag, given 256 -bit permutation state, see
// `TAGτ (T0)` algorithm defined in figure 3.6 of Photon-Beetle specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/photon-beetle-spec-final.pdf
template<const size_t OUT>
inline static void
_gen_tag(uint8_t* const __restrict state, // 8x4 permutation state
         uint8_t* const __restrict tag    // OUT -bytes tag | OUT ∈ {16, 32}
         )
  requires(check_out(OUT))
{
  if constexpr (OUT == 16) {
    static_assert(OUT == 16, "Must compute 128 -bit tag !");

    photon::_photon256(state);
    std::memcpy(tag, state, OUT);
  } else {
    static_assert(OUT == 32, "Must compute 256 -bit tag !");

    photon::_photon256(state);
    std::memcpy(tag, state, OUT / 2);

    photon::_photon256(state);
    std::memcpy(tag + (OUT / 2), state, OUT / 2);
  }
}

// Shuffle RATE portion of 8x8 permutation state ( 256 -bit wide ), see
// section 3.1 of Photon-Beetle specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/photon-beetle-spec-final.pdf
template<const size_t RATE>
inline static void
shuffle(const uint8_t* const __restrict state,
        uint8_t* const __restrict shuffled)
  requires(check_rate(RATE))
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

// Shuffle RATE ( must ∈ {4, 16} ) portion of 8x4 permutation state, see
// section 3.1 ( and figure 3.1, where shuffle routine is defined ) of
// Photon-Beetle specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/photon-beetle-spec-final.pdf
template<const size_t RATE>
inline static void
_shuffle(const uint8_t* const __restrict state,
         uint8_t* const __restrict shuffled)
  requires(check_rate(RATE))
{
  if constexpr (RATE == 4) {
    static_assert(RATE == 4, "Rate portion of state must be 32 -bit wide");

    if constexpr (std::endian::native == std::endian::little) {
      uint16_t s1;
      std::memcpy(&s1, state, RATE / 2);

      const auto s1_prime = std::rotr(s1, 1);
      std::memcpy(shuffled, state + (RATE / 2), RATE / 2);
      std::memcpy(shuffled + (RATE / 2), &s1_prime, RATE / 2);
    } else {
      const uint16_t s1 = (static_cast<uint16_t>(state[1]) << 8) |
                          (static_cast<uint16_t>(state[0]) << 0);

      const auto s1_prime = std::rotr(s1, 1);
      std::memcpy(shuffled, state + (RATE / 2), RATE / 2);
      shuffled[2] = static_cast<uint8_t>(s1_prime);
      shuffled[3] = static_cast<uint8_t>(s1_prime >> 8);
    }
  } else {
    static_assert(RATE == 16, "Rate portion of state must be 128 -bit wide");

    if constexpr (std::endian::native == std::endian::little) {
      uint64_t s1;
      std::memcpy(&s1, state, RATE / 2);

      const auto s1_prime = std::rotr(s1, 1);
      std::memcpy(shuffled, state + (RATE / 2), RATE / 2);
      std::memcpy(shuffled + (RATE / 2), &s1_prime, RATE / 2);
    } else {
      uint64_t s1;
      for (size_t i = 0; i < RATE / 2; i++) {
        s1 |= static_cast<uint64_t>(state[i]) << (i * 8);
      }

      const auto s1_prime = std::rotr(s1, 1);
      std::memcpy(shuffled, state + (RATE / 2), RATE / 2);

      for (size_t i = 0; i < RATE / 2; i++) {
        shuffled[(RATE / 2) + i] = static_cast<uint8_t>(s1_prime >> (i * 8));
      }
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
  requires(check_rate(RATE))
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

// Linear function `ρ` used during authenticated encryption, as defined in
// section 3.1 of Photon-Beetle specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/photon-beetle-spec-final.pdf
template<const size_t RATE>
inline static void
_rho(uint8_t* const __restrict state,     // 8x4 permutation state
     const uint8_t* const __restrict txt, // plain text
     uint8_t* const __restrict enc,       // encrypted bytes
     const size_t tlen                    // = len(txt) = len(txt) | <= RATE
     )
  requires(check_rate(RATE))
{
  uint8_t shuffled[RATE];
  _shuffle<RATE>(state, shuffled);

#if defined __clang__
#pragma unroll
#elif defined __GNUG__
#pragma GCC ivdep
#endif
  for (size_t i = 0; i < tlen; i++) {
    enc[i] = shuffled[i] ^ txt[i];
    state[i] ^= txt[i];
  }

  constexpr uint8_t br[]{ 0, 1 };
  state[tlen] ^= br[tlen < RATE];
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
  requires(check_rate(RATE))
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
