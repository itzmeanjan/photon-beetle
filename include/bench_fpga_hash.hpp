#pragma once
#include "fpga_hash.hpp"
#include "sycl_utils.hpp"
#include "utils.hpp"

// Benchmark Photon-Beetle-Hash implementation on FPGA, while measuring time to
// transfer data host -> device & vice versa, time to finish offloaded
// computation. Along with that this routine also measures how much data is
// transferred between host & device and how much data is processed by offloaded
// kernel. With both of these information ( i.e. amount of data in terms of
// bytes and time to finish computation/ data tx ) one can compute processing/
// transfer bandwidth ( say bytes/ second )
//
// Ensure SYCL queue has profiling enabled, which will be used for timing
// execution of SYCL events
static void
bench_photon_beetle_hash_fpga(
  sycl::queue& q,                // SYCL queue
  const size_t per_wi_mlen,      // each independent message slice length
  const size_t wi_cnt,           // # -of independent input message slices
  uint64_t* const __restrict ts, // measured time durations
  size_t* const __restrict io    // measured amount of bytes processed
)
{
  assert(q.has_property<sycl::property::queue::enable_profiling>());

  using evt = sycl::event;

  const size_t mlen = wi_cnt * per_wi_mlen;
  const size_t dlen = wi_cnt << 5;

  // acquire memory resources
  uint8_t* msg_h = static_cast<uint8_t*>(std::malloc(mlen));
  uint8_t* dig_h = static_cast<uint8_t*>(std::malloc(dlen));

  uint8_t* msg_d = static_cast<uint8_t*>(sycl::malloc_device(mlen, q));
  uint8_t* dig_d = static_cast<uint8_t*>(sycl::malloc_device(dlen, q));

  random_data(msg_h, mlen);

  using namespace fpga_photon_beetle;

  // host -> device data tx
  evt e0 = q.memcpy(msg_d, msg_h, mlen);

  // compute on FPGA
  evt e1 = hash(q, msg_d, mlen, dig_d, dlen, wi_cnt, per_wi_mlen, 32, { e0 });

  // device -> host data tx
  evt e2 = q.submit([&](sycl::handler& h) {
    h.depends_on(e1);
    h.memcpy(dig_h, dig_d, dlen);
  });

  // host synchronization
  e2.wait();

  // host -> device
  ts[0] = time_event(e0);
  io[0] = mlen;

  // compute
  ts[1] = time_event(e1);
  io[1] = mlen;

  // device -> host
  ts[2] = time_event(e2);
  io[2] = dlen;

  // deallocate memory resources
  std::free(msg_h);
  std::free(dig_h);

  sycl::free(msg_d, q);
  sycl::free(dig_d, q);
}
