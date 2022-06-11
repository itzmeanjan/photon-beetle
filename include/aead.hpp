#pragma once
#include "common.hpp"
#include <algorithm>

// Photon-Beetle-{Hash, AEAD} function(s)
namespace photon_beetle {

// Given 16 -bytes secret key, 16 -bytes public message nonce, N (>=0) -bytes
// associated data &  M(>=0) -bytes plain text, this routine computes M -bytes
// ciphex text & 16 -bytes authentication tag using Photon-Beetle authenticated
// encryption algorithm
//
// RATE is in terms of bytes, allowed values are {4, 16}.
//
// Note, avoid reusing same nonce under same secret key !
//
// See algorithm `PHOTON-Beetle-AEAD.ENC[r](K, N, A, M)` defined in figure 3.6
// of Photon-Beetle specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/photon-beetle-spec-final.pdf
template<const size_t RATE>
inline static void
encrypt(
  const uint8_t* const __restrict key,   // 16 -bytes secret key
  const uint8_t* const __restrict nonce, // 16 -bytes public message nonce
  const uint8_t* const __restrict data,  // N -bytes associated data | N >= 0
  const size_t dlen,                     // len(data) >= 0
  const uint8_t* const __restrict txt,   // N -bytes plain text | N >= 0
  uint8_t* const __restrict enc,         // N -bytes cipher text | N >= 0
  const size_t mlen,                     // len(txt) = len(enc) >= 0
  uint8_t* const __restrict tag          // 16 -bytes authentication tag
)
{
  static_assert((RATE == 4) || (RATE == 16), "Only Photon-Beetle-AEAD{32,128}");

  uint8_t state[64] = {};

  for (size_t i = 0; i < 16; i++) {
    const size_t off0 = i << 1;
    const size_t off1 = 32ul ^ off0;

    state[off0] = nonce[i] & photon::LS4B;
    state[off0 ^ 1] = nonce[i] >> 4;

    state[off1] = key[i] & photon::LS4B;
    state[off1 ^ 1] = key[i] >> 4;
  }

  if ((dlen == 0ul) && (mlen == 0ul)) {
    state[63] ^= 1 << 1;
    gen_tag<16ul>(state, tag);

    return;
  }

  const bool f0 = mlen > 0;
  const bool f1 = (dlen & (RATE - 1)) == 0;

  const uint8_t C0 = (f0 && f1) ? 1 : f0 ? 2 : f1 ? 3 : 4;

  const bool f2 = dlen > 0;
  const bool f3 = (mlen & (RATE - 1)) == 0;

  const uint8_t C1 = (f2 && f3) ? 1 : f2 ? 2 : f3 ? 5 : 6;

  if (dlen > 0) {
    absorb<RATE>(state, data, dlen, C0);
  }

  if (mlen > 0) {
    for (size_t i = 0; i < mlen; i += RATE) {
      photon::photon256(state);
      rho<RATE>(state, txt + i, enc + i, std::min(RATE, mlen - i));
    }

    const uint8_t y = (state[63] << 4) | (state[62] & photon::LS4B);
    const uint8_t w = y ^ (C1 << 5);

    state[62] = w & photon::LS4B;
    state[63] = w >> 4;
  }

  gen_tag<16ul>(state, tag);
}

}
