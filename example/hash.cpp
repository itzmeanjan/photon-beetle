#include "photon_beetle.hpp"
#include <iostream>

// Compile it with
//
// g++ -std=c++20 -Wall -O3 -march=native -I ./include example/hash.cpp
int
main()
{
  constexpr size_t mlen = 64;                        // message length in bytes
  constexpr size_t dlen = photon_beetle::DIGEST_LEN; // digest length in bytes

  // allocate memory on heap
  uint8_t* msg = static_cast<uint8_t*>(std::malloc(mlen));
  uint8_t* dig = static_cast<uint8_t*>(std::malloc(dlen));

  photon_utils::random_data(msg, mlen); // generate random message bytes
  std::memset(dig, 0, dlen);            // set digest to zero bytes

  // compute Photon-Beetle hash
  photon_beetle::hash(msg, mlen, dig);

  std::cout << "Input   : " << photon_utils::to_hex(msg, mlen) << std::endl;
  std::cout << "Output  : " << photon_utils::to_hex(dig, dlen) << std::endl;

  // release acquired memory resources
  std::free(msg);
  std::free(dig);

  return EXIT_SUCCESS;
}
