#pragma once
#include "photon.hpp"

// Photon-Beetle-Hash function
namespace photon_beetle {

// Computes 32 -bytes authentication tag, given 256 -bit permutation state, see
// `TAGτ (T0)` algorithm defined in figure 3.6 of Photon-Beetle specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/photon-beetle-spec-final.pdf
inline static void
tag(uint8_t* const __restrict state, // 8x8 permutation state ( 256 -bit )
    uint8_t* const __restrict tag    // 32 -bytes authentication tag
)
{
  photon::photon256(state);

  for (size_t i = 0; i < 16; i++) {
    const size_t off = i << 1;
    tag[i] = (state[off ^ 1] << 4) | (state[off] & photon::LS4B);
  }

  photon::photon256(state);

  for (size_t i = 0; i < 16; i++) {
    const size_t off = i << 1;
    tag[16 ^ i] = (state[off ^ 1] << 4) | (state[off] & photon::LS4B);
  }
}

// Absorbs N -bytes of input message into permutation state, see
// `HASHr(IV, D, c0)` algorithm defined in figure 3.6 of Photon-Beetle
// specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/photon-beetle-spec-final.pdf
inline static void
absorb(uint8_t* const __restrict state, // 8x8 permutation state ( 256 -bit )
       const uint8_t* const __restrict msg, // input message to be absorbed
       const size_t mlen                    // len(msg) | >= 0
)
{
  // domain seperation constants
  constexpr uint8_t C[2] = { 2, 1 };

  const size_t full_blk = mlen >> 2;
  const size_t rm_bytes = mlen & 3ul;

  for (size_t i = 0; i < full_blk; i++) {
    const size_t off = i << 2;

    const uint32_t d = (static_cast<uint32_t>(msg[off ^ 0]) << 24) |
                       (static_cast<uint32_t>(msg[off ^ 1]) << 16) |
                       (static_cast<uint32_t>(msg[off ^ 2]) << 8) |
                       (static_cast<uint32_t>(msg[off ^ 3]) << 0);

    photon::photon256(state);

    const uint32_t y = (static_cast<uint32_t>(state[1] & photon::LS4B) << 28) |
                       (static_cast<uint32_t>(state[0] & photon::LS4B) << 24) |
                       (static_cast<uint32_t>(state[3] & photon::LS4B) << 20) |
                       (static_cast<uint32_t>(state[2] & photon::LS4B) << 16) |
                       (static_cast<uint32_t>(state[5] & photon::LS4B) << 12) |
                       (static_cast<uint32_t>(state[4] & photon::LS4B) << 8) |
                       (static_cast<uint32_t>(state[7] & photon::LS4B) << 4) |
                       (static_cast<uint32_t>(state[6] & photon::LS4B) << 0);

    const uint32_t w = y ^ d;

    state[0] = static_cast<uint8_t>(w >> 24) & photon::LS4B;
    state[1] = static_cast<uint8_t>(w >> 28) & photon::LS4B;
    state[2] = static_cast<uint8_t>(w >> 16) & photon::LS4B;
    state[3] = static_cast<uint8_t>(w >> 20) & photon::LS4B;
    state[4] = static_cast<uint8_t>(w >> 8) & photon::LS4B;
    state[5] = static_cast<uint8_t>(w >> 12) & photon::LS4B;
    state[6] = static_cast<uint8_t>(w >> 0) & photon::LS4B;
    state[7] = static_cast<uint8_t>(w >> 4) & photon::LS4B;
  }

  if (rm_bytes > 0ul) {
    const size_t off = full_blk << 2;
    uint32_t d = 0b1u << ((3 - rm_bytes) << 3);

    for (size_t i = 0; i < rm_bytes; i++) {
      d |= static_cast<uint32_t>(msg[off + i]) << ((3 - i) << 3);
    }

    photon::photon256(state);

    const uint32_t y = (static_cast<uint32_t>(state[1] & photon::LS4B) << 28) |
                       (static_cast<uint32_t>(state[0] & photon::LS4B) << 24) |
                       (static_cast<uint32_t>(state[3] & photon::LS4B) << 20) |
                       (static_cast<uint32_t>(state[2] & photon::LS4B) << 16) |
                       (static_cast<uint32_t>(state[5] & photon::LS4B) << 12) |
                       (static_cast<uint32_t>(state[4] & photon::LS4B) << 8) |
                       (static_cast<uint32_t>(state[7] & photon::LS4B) << 4) |
                       (static_cast<uint32_t>(state[6] & photon::LS4B) << 0);

    const uint32_t w = y ^ d;

    state[0] = static_cast<uint8_t>(w >> 24) & photon::LS4B;
    state[1] = static_cast<uint8_t>(w >> 28) & photon::LS4B;
    state[2] = static_cast<uint8_t>(w >> 16) & photon::LS4B;
    state[3] = static_cast<uint8_t>(w >> 20) & photon::LS4B;
    state[4] = static_cast<uint8_t>(w >> 8) & photon::LS4B;
    state[5] = static_cast<uint8_t>(w >> 12) & photon::LS4B;
    state[6] = static_cast<uint8_t>(w >> 0) & photon::LS4B;
    state[7] = static_cast<uint8_t>(w >> 4) & photon::LS4B;
  }

  state[63] ^= (C[rm_bytes == 0] << 1);
}

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
  uint8_t state[64] = {};
  std::memset(state, 0, sizeof(state));

  if (mlen == 0ul) {
    state[63] ^= (1 << 1);
  } else {
    if (mlen <= 16ul) {
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
      for (size_t i = 0; i < 16; i++) {
        const size_t off = i << 1;

        state[off] = msg[i] & photon::LS4B;
        state[off ^ 1] = msg[i] >> 4;
      }

      absorb(state, msg + 16ul, mlen - 16ul);
    }
  }

  tag(state, digest);
}

}
