#include "hash.hpp"
#include "utils.hpp"
#include <iostream>

// Compile it with
//
// g++ -std=c++20 -Wall -I ./include example/hash.cpp
int
main()
{
  constexpr size_t mlen = 64; // message length in bytes
  constexpr size_t dlen = 32; // digest length in bytes

  // allocate memory on heap
  uint8_t* msg = static_cast<uint8_t*>(std::malloc(mlen));
  uint8_t* dig = static_cast<uint8_t*>(std::malloc(dlen));

  random_data(msg, mlen);    // generate random message bytes
  std::memset(dig, 0, dlen); // set digest to zero bytes

  // compute Photon-Beetle hash
  photon_beetle::hash(msg, mlen, dig);

  std::cout << "Input   : " << to_hex(msg, mlen) << std::endl;
  std::cout << "Output  : " << to_hex(dig, dlen) << std::endl;

  // release acquired memory resources
  std::free(msg);
  std::free(dig);

  return EXIT_SUCCESS;
}
