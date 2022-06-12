#include "aead.hpp"
#include "hash.hpp"

// Thin C wrapper on top of underlying C++ implementation of
// Photon-Beetle-{Hash, AEAD} functions, which can be used for producing shared
// library object with C-ABI & used from other languages such as Rust, Python

// Function prototype
extern "C"
{
  void photon_beetle_hash(const uint8_t* const __restrict,
                          const size_t,
                          uint8_t* const __restrict);

  void photon_beetle_32_encrypt(const uint8_t* const __restrict,
                                const uint8_t* const __restrict,
                                const uint8_t* const __restrict,
                                const size_t,
                                const uint8_t* const __restrict,
                                uint8_t* const __restrict,
                                const size_t,
                                uint8_t* const __restrict);

  bool photon_beetle_32_decrypt(const uint8_t* const __restrict,
                                const uint8_t* const __restrict,
                                const uint8_t* const __restrict,
                                const uint8_t* const __restrict,
                                const size_t,
                                const uint8_t* const __restrict,
                                uint8_t* const __restrict,
                                const size_t);

  void photon_beetle_128_encrypt(const uint8_t* const __restrict,
                                 const uint8_t* const __restrict,
                                 const uint8_t* const __restrict,
                                 const size_t,
                                 const uint8_t* const __restrict,
                                 uint8_t* const __restrict,
                                 const size_t,
                                 uint8_t* const __restrict);

  bool photon_beetle_128_decrypt(const uint8_t* const __restrict,
                                 const uint8_t* const __restrict,
                                 const uint8_t* const __restrict,
                                 const uint8_t* const __restrict,
                                 const size_t,
                                 const uint8_t* const __restrict,
                                 uint8_t* const __restrict,
                                 const size_t);
}

// Function implementation
extern "C"
{
  // Given N (>=0) -bytes input message, this routines computes 32 -bytes output
  // digest, using Photon-Beetle hashing algorithm
  void photon_beetle_hash(const uint8_t* const __restrict in,
                          const size_t ilen,
                          uint8_t* const __restrict out)
  {
    photon_beetle::hash(in, ilen, out);
  }

  // Given 16 -bytes secret key, 16 -bytes nonce, N -bytes plain text & M -bytes
  // associated data, this routine computes N -bytes cipher text & 16 -bytes
  // authentication tag, using Photon-Beetle-AEAD[32] algorithm | N, M >= 0
  void photon_beetle_32_encrypt(const uint8_t* const __restrict key,
                                const uint8_t* const __restrict nonce,
                                const uint8_t* const __restrict data,
                                const size_t d_len,
                                const uint8_t* const __restrict txt,
                                uint8_t* const __restrict enc,
                                const size_t ct_len,
                                uint8_t* const __restrict tag)
  {
    photon_beetle::encrypt<4>(key, nonce, data, d_len, txt, enc, ct_len, tag);
  }

  // Given 16 -bytes secret key, 16 -bytes nonce, 16 -bytes authentication tag,
  // N -bytes cipher text & M -bytes associated data, this routine computes N
  // -bytes deciphered text & a boolean verification flag, using
  // Photon-Beetle-AEAD[32] algorithm | N, M >= 0
  //
  // Before consuming decrypted bytes ensure presence of truth value in returned
  // boolean flag !
  bool photon_beetle_32_decrypt(const uint8_t* const __restrict key,
                                const uint8_t* const __restrict nonce,
                                const uint8_t* const __restrict tag,
                                const uint8_t* const __restrict data,
                                const size_t d_len,
                                const uint8_t* const __restrict enc,
                                uint8_t* const __restrict dec,
                                const size_t ct_len)
  {
    using namespace photon_beetle;
    return decrypt<4>(key, nonce, tag, data, d_len, enc, dec, ct_len);
  }

  // Given 16 -bytes secret key, 16 -bytes nonce, N -bytes plain text & M -bytes
  // associated data, this routine computes N -bytes cipher text & 16 -bytes
  // authentication tag, using Photon-Beetle-AEAD[128] algorithm | N, M >= 0
  void photon_beetle_128_encrypt(const uint8_t* const __restrict key,
                                 const uint8_t* const __restrict nonce,
                                 const uint8_t* const __restrict data,
                                 const size_t d_len,
                                 const uint8_t* const __restrict txt,
                                 uint8_t* const __restrict enc,
                                 const size_t ct_len,
                                 uint8_t* const __restrict tag)
  {
    photon_beetle::encrypt<16>(key, nonce, data, d_len, txt, enc, ct_len, tag);
  }

  // Given 16 -bytes secret key, 16 -bytes nonce, 16 -bytes authentication tag,
  // N -bytes cipher text & M -bytes associated data, this routine computes N
  // -bytes deciphered text & a boolean verification flag, using
  // Photon-Beetle-AEAD[128] algorithm | N, M >= 0
  //
  // Before consuming decrypted bytes ensure presence of truth value in returned
  // boolean flag !
  bool photon_beetle_128_decrypt(const uint8_t* const __restrict key,
                                 const uint8_t* const __restrict nonce,
                                 const uint8_t* const __restrict tag,
                                 const uint8_t* const __restrict data,
                                 const size_t d_len,
                                 const uint8_t* const __restrict enc,
                                 uint8_t* const __restrict dec,
                                 const size_t ct_len)
  {
    using namespace photon_beetle;
    return decrypt<16>(key, nonce, tag, data, d_len, enc, dec, ct_len);
  }
}
