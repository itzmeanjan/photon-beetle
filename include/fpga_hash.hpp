#pragma once
#include "hash.hpp"
#include <CL/sycl.hpp>
#include <cassert>

// Photon-Beetle-{Hash, AEAD} function(s) targeting FPGA powered by SYCL
namespace fpga_photon_beetle {

// Predeclared kernel name to avoid kernel name mangling in optimization report
class kernelPhotonBeetleHash;

// Photon-Beetle-Hash on FPGA powered by SYCL
//
// Given N -many independent byteslices, each of length M (>=0) -bytes, this
// routine computes Photon-Beetle-Hash on each of these byteslices, producing N
// -many 32 -bytes digests, while offloading whole computation to FPGA, executed
// in deeply pipelined fashion, invoking `photon_beetle::hash` N -many times
// on non-overlapping byte boundaries & writing output digest on non-overlapping
// byte boundaries
//
// Note this function takes a vector of SYCL events, which can be passed by
// caller to make offloaded kernel wait until they complete
//
// Similarly this routine returns one SYCL event which can be used to wait for
// completion of offloaded computation
//
// Note, in function signature all data lengths are in terms of `bytes` !
static sycl::event
hash(sycl::queue& q,                      // SYCL queue for job submission
     const uint8_t* const __restrict msg, // input to be hashed
     const size_t mlen,                   // len(msg) = wi_cnt * per_wi_mlen
     uint8_t* const __restrict dig,       // output digests
     const size_t dlen,                   // len(dig) = wi_cnt * per_wi_dlen
     const size_t wi_cnt,      // # -of independent byteslices to be hashed = N
     const size_t per_wi_mlen, // each input byteslice of length
     const size_t per_wi_dlen, // each output byteslice of length
     const std::vector<sycl::event> evts // SYCL events to wait for
)
{
  assert(per_wi_dlen == 1ul << 5);
  assert(mlen == wi_cnt * per_wi_mlen);
  assert(dlen == wi_cnt << 5);

  const sycl::event evt = q.submit([&](sycl::handler& h) {
    h.depends_on(evts);
    h.single_task<kernelPhotonBeetleHash>(
      [=]() [[intel::kernel_args_restrict]] {
        [[intel::ivdep]] for (size_t i = 0; i < wi_cnt; i++)
        {
          const size_t moff = per_wi_mlen * i;
          const size_t doff = i << 5;

          photon_beetle::hash(msg + moff, per_wi_mlen, dig + doff);
        }
      });
  });

  return evt;
}

}
