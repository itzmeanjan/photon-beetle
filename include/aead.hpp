#pragma once
#include "common.hpp"
#include <cstring>

// Photon-Beetle-{Hash, AEAD} function(s)
namespace photon_beetle {

using uint128_t = unsigned __int128;

// Given expected authentication tag ( input for decrypt routine ) and computed
// tag ( computed during decryption ), this routine performs a byte-wise match
// between those two byte arrays and returns boolean truth value if they match.
// Otherwise it returns false.
inline static bool
verify_tag(const uint8_t* const __restrict expected, // 16 -bytes
           const uint8_t* const __restrict computed  // 16 -bytes
)
{
  uint128_t v0, v1;

  std::memcpy(&v0, expected, sizeof(v0));
  std::memcpy(&v1, computed, sizeof(v1));

  return !static_cast<bool>(v0 ^ v1);
}

// Given 16 -bytes secret key, 16 -bytes public message nonce, N (>=0) -bytes
// associated data & M (>=0) -bytes plain text, this routine computes M -bytes
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
  requires(photon_common::check_rate(RATE))
{
  uint8_t state[32];

  std::memcpy(state, nonce, 16);
  std::memcpy(state + 16, key, 16);

  if ((dlen == 0) && (mlen == 0)) [[unlikely]] {
    state[31] ^= (1 << 5);
    photon_common::gen_tag<16>(state, tag);

    return;
  }

  const bool f0 = mlen > 0;
  const bool f1 = (dlen & (RATE - 1)) == 0;
  const bool f2 = dlen > 0;
  const bool f3 = (mlen & (RATE - 1)) == 0;

  const uint8_t C0 = (f0 && f1) ? 1 : f0 ? 2 : f1 ? 3 : 4;
  const uint8_t C1 = (f2 && f3) ? 1 : f2 ? 2 : f3 ? 5 : 6;

  if (dlen > 0) [[likely]] {
    photon_common::absorb<RATE>(state, data, dlen, C0);
  }

  if (mlen > 0) [[likely]] {
    for (size_t off = 0; off < mlen; off += RATE) {
      photon::photon256(state);

      const auto len = std::min(RATE, mlen - off);
      photon_common::rho<RATE>(state, txt + off, enc + off, len);
    }

    state[31] ^= (C1 << 5);
  }

  photon_common::gen_tag<16>(state, tag);
}

// Given 16 -bytes secret key, 16 -bytes public message nonce, 16 -bytes
// authentication tag, N (>=0) -bytes associated data & M (>=0) -bytes cipher
// text, this routine computes M -bytes plain text & boolean verification flag
// using Photon-Beetle verified decryption algorithm
//
// RATE is in terms of bytes, allowed values are {4, 16}.
//
// Note, before consuming decrypted bytes ensure presence of truth value in
// returned boolean flag !
//
// See algorithm `PHOTON-Beetle-AEAD.DEC[r](K, N, A, C, T)` defined in
// figure 3.6 of Photon-Beetle specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/photon-beetle-spec-final.pdf
template<const size_t RATE>
inline static bool
decrypt(
  const uint8_t* const __restrict key,   // 16 -bytes secret key
  const uint8_t* const __restrict nonce, // 16 -bytes public message nonce
  const uint8_t* const __restrict tag,   // 16 -bytes authentication tag
  const uint8_t* const __restrict data,  // N -bytes associated data | N >= 0
  const size_t dlen,                     // len(data) >= 0
  const uint8_t* const __restrict enc,   // N -bytes cipher text | N >= 0
  uint8_t* const __restrict txt,         // N -bytes decrypted text | N >= 0
  const size_t mlen                      // len(enc) = len(txt) >= 0
  )
  requires(photon_common::check_rate(RATE))
{
  uint8_t state[32];
  uint8_t tag_[16];

  std::memcpy(state, nonce, 16);
  std::memcpy(state + 16, key, 16);

  if ((dlen == 0) && (mlen == 0)) [[unlikely]] {
    state[31] ^= (1 << 5);
    photon_common::gen_tag<16>(state, tag_);

    return verify_tag(tag, tag_);
  }

  const bool f0 = mlen > 0;
  const bool f1 = (dlen & (RATE - 1)) == 0;
  const bool f2 = dlen > 0;
  const bool f3 = (mlen & (RATE - 1)) == 0;

  const uint8_t C0 = (f0 && f1) ? 1 : f0 ? 2 : f1 ? 3 : 4;
  const uint8_t C1 = (f2 && f3) ? 1 : f2 ? 2 : f3 ? 5 : 6;

  if (dlen > 0) [[likely]] {
    photon_common::absorb<RATE>(state, data, dlen, C0);
  }

  if (mlen > 0) [[likely]] {
    for (size_t off = 0; off < mlen; off += RATE) {
      photon::photon256(state);

      const auto len = std::min(RATE, mlen - off);
      photon_common::inv_rho<RATE>(state, enc + off, txt + off, len);
    }

    state[31] ^= (C1 << 5);
  }

  photon_common::gen_tag<16>(state, tag_);
  const auto flg = verify_tag(tag, tag_);
  std::memset(txt, 0, !flg * mlen);

  return flg;
}

}
