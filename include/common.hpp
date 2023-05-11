#pragma once
#include "photon.hpp"
#include <algorithm>

// Common dependency functions used in Photon-Beetle-{Hash, AEAD}
namespace photon_common {

static_assert(__SIZEOF_INT128__ == 16, "128 -bit unsigned integer is needed !");
using uint128_t = unsigned __int128;

// Compile-time check for ensuring that RATE ∈ {4, 16}
consteval bool
check_rate(const size_t rate)
{
  return (rate == 4) || (rate == 16);
}

// Compile-time check for ensuring that OUT ∈ {16, 32}
consteval bool
check_out(const size_t out)
{
  return (out == 16) || (out == 32);
}

// Absorbs N (>=0) -bytes of input message into permutation state, see
// `HASH<RATE>(IV, D, c0)` algorithm defined in figure 3.6 of Photon-Beetle
// specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/photon-beetle-spec-final.pdf
template<const size_t RATE>
inline static void
absorb(uint8_t* const __restrict state,     // 8x4 permutation state
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
      photon::photon256(state);

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
      photon::photon256(state);

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
      photon::photon256(state);

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
      photon::photon256(state);

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
gen_tag(uint8_t* const __restrict state, // 8x4 permutation state
        uint8_t* const __restrict tag    // OUT -bytes tag | OUT ∈ {16, 32}
        )
  requires(check_out(OUT))
{
  if constexpr (OUT == 16) {
    static_assert(OUT == 16, "Must compute 128 -bit tag !");

    photon::photon256(state);
    std::memcpy(tag, state, OUT);
  } else {
    static_assert(OUT == 32, "Must compute 256 -bit tag !");

    photon::photon256(state);
    std::memcpy(tag, state, OUT / 2);

    photon::photon256(state);
    std::memcpy(tag + (OUT / 2), state, OUT / 2);
  }
}

// Shuffle RATE ( must ∈ {4, 16} ) portion of 8x4 permutation state, see
// section 3.1 ( and figure 3.1, where shuffle routine is defined ) of
// Photon-Beetle specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/photon-beetle-spec-final.pdf
template<const size_t RATE>
inline static void
shuffle(const uint8_t* const __restrict state,
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
rho(uint8_t* const __restrict state,     // 8x4 permutation state
    const uint8_t* const __restrict txt, // plain text
    uint8_t* const __restrict enc,       // encrypted bytes
    const size_t tlen                    // = len(txt) = len(txt) | <= RATE
    )
  requires(check_rate(RATE))
{
  uint8_t shuffled[RATE];
  shuffle<RATE>(state, shuffled);

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
inv_rho(uint8_t* const __restrict state,     // 8x4 permutation state
        const uint8_t* const __restrict enc, // encrypted text
        uint8_t* const __restrict txt,       // plain text
        const size_t tlen                    // = len(enc) = len(txt) | <= RATE
        )
  requires(check_rate(RATE))
{
  uint8_t shuffled[RATE];
  shuffle<RATE>(state, shuffled);

#if defined __clang__
#pragma unroll
#elif defined __GNUG__
#pragma GCC ivdep
#endif
  for (size_t i = 0; i < tlen; i++) {
    txt[i] = shuffled[i] ^ enc[i];
    state[i] ^= txt[i];
  }

  constexpr uint8_t br[]{ 0, 1 };
  state[tlen] ^= br[tlen < RATE];
}

}
