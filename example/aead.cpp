#include "photon_beetle.hpp"
#include <cassert>
#include <iostream>

// Compile it with
//
// g++ -std=c++20 -Wall -O3 -march=native -I ./include example/aead.cpp
int
main()
{
  // Rate bytes of Photon-Beetle-AEAD-32 ( default ).
  // You may also make R = 16, to use Photon-Beetle-AEAD-128
  constexpr size_t R = 4;

  // either Photon-Beetle-AEAD-32 or Photon-Beetle-AEAD-128
  static_assert((R == 4) || (R == 16));

  constexpr size_t mlen = 64; // plain/ cipher text length in bytes
  constexpr size_t dlen = 32; // associated data length in bytes

  // acquire memory resources
  uint8_t* key = static_cast<uint8_t*>(std::malloc(photon_beetle::KEY_LEN));
  uint8_t* nonce = static_cast<uint8_t*>(std::malloc(photon_beetle::NONCE_LEN));
  uint8_t* tag = static_cast<uint8_t*>(std::malloc(photon_beetle::TAG_LEN));
  uint8_t* dat = static_cast<uint8_t*>(std::malloc(dlen));
  uint8_t* txt = static_cast<uint8_t*>(std::malloc(mlen));
  uint8_t* enc = static_cast<uint8_t*>(std::malloc(mlen));
  uint8_t* dec = static_cast<uint8_t*>(std::malloc(mlen));

  // generate random inputs i.e. key, nonce, associated data and text
  photon_utils::random_data(key, photon_beetle::KEY_LEN);
  photon_utils::random_data(nonce, photon_beetle::NONCE_LEN);
  photon_utils::random_data(dat, dlen);
  photon_utils::random_data(txt, mlen);

  // clean to be written memory allocations
  std::memset(tag, 0, photon_beetle::TAG_LEN);
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

  using namespace photon_utils;
  std::cout << "Key      : " << to_hex(key, photon_beetle::KEY_LEN) << "\n";
  std::cout << "Nonce    : " << to_hex(nonce, photon_beetle::NONCE_LEN) << "\n";
  std::cout << "Data     : " << to_hex(dat, dlen) << "\n";
  std::cout << "Text     : " << to_hex(txt, mlen) << "\n";
  std::cout << "Tag      : " << to_hex(tag, photon_beetle::TAG_LEN) << "\n";
  std::cout << "Cipher   : " << to_hex(enc, mlen) << "\n";
  std::cout << "Decrypted: " << to_hex(dec, mlen) << "\n";

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
