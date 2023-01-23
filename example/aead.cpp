#include "aead.hpp"
#include "utils.hpp"
#include <cassert>
#include <iostream>

// Compile it with
//
// g++ -std=c++20 -Wall -O3 -march=native -I ./include example/aead.cpp
int
main()
{
  constexpr size_t R = 4; // rate bytes of Photon-Beetle-AEAD-32 ( default )

  // either Photon-Beetle-AEAD-32 or Photon-Beetle-AEAD-128
  static_assert((R == 4) || (R == 16));

  constexpr size_t mlen = 64; // plain/ cipher text length in bytes
  constexpr size_t dlen = 32; // associated data length in bytes

  // acquire memory resources
  uint8_t* key = static_cast<uint8_t*>(std::malloc(16));
  uint8_t* nonce = static_cast<uint8_t*>(std::malloc(16));
  uint8_t* tag = static_cast<uint8_t*>(std::malloc(16));
  uint8_t* dat = static_cast<uint8_t*>(std::malloc(dlen));
  uint8_t* txt = static_cast<uint8_t*>(std::malloc(mlen));
  uint8_t* enc = static_cast<uint8_t*>(std::malloc(mlen));
  uint8_t* dec = static_cast<uint8_t*>(std::malloc(mlen));

  photon_utils::random_data(key, 16);   // generate random key
  photon_utils::random_data(nonce, 16); // generate random nonce
  photon_utils::random_data(dat, dlen); // generate random associated data
  photon_utils::random_data(txt, mlen); // generate random plain text

  // clean to be written memory allocations
  std::memset(tag, 0, 16);
  std::memset(enc, 0, mlen);
  std::memset(dec, 0, mlen);

  bool f = false;

  // encrypt plain text ( never encrypts associated data )
  photon_beetle::encrypt<R>(key, nonce, dat, dlen, txt, enc, mlen, tag);
  // decrypt back to plain text
  f = photon_beetle::decrypt<R>(key, nonce, tag, dat, dlen, enc, dec, mlen);

  // verify authenticity & integrity check !
  assert(f);

  // verify plain text & decrypted data ( byte-by-byte )
  for (size_t i = 0; i < mlen; i++) {
    assert((txt[i] ^ dec[i]) == 0);
  }

  std::cout << "Key         : " << photon_utils::to_hex(key, 16) << std::endl;
  std::cout << "Nonce       : " << photon_utils::to_hex(nonce, 16) << std::endl;
  std::cout << "Data        : " << photon_utils::to_hex(dat, dlen) << std::endl;
  std::cout << "Text        : " << photon_utils::to_hex(txt, mlen) << std::endl;
  std::cout << "Tag         : " << photon_utils::to_hex(tag, 16) << std::endl;
  std::cout << "Cipher      : " << photon_utils::to_hex(enc, mlen) << std::endl;
  std::cout << "Decrypted   : " << photon_utils::to_hex(dec, mlen) << std::endl;

  // memory resources being released
  std::free(key);
  std::free(nonce);
  std::free(tag);
  std::free(dat);
  std::free(txt);
  std::free(enc);
  std::free(dec);

  return EXIT_SUCCESS;
}
