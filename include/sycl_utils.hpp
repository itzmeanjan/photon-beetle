#pragma once
#include <CL/sycl.hpp>

constexpr double GB = 1073741824.; // 1 << 30 bytes
constexpr double MB = 1048576.;    // 1 << 20 bytes
constexpr double KB = 1024.;       // 1 << 10 bytes

// Time execution of SYCL command, whose submission resulted into given SYCL
// event, in nanosecond level granularity
//
// Ensure SYCL queue, onto which command was submitted, has profiling enabled !
//
// Taken from
// https://github.com/itzmeanjan/acorn/blob/1982a24d69513cde6c4d74ee2ad2bd25745bd865/include/bench_utils.hpp#L22-L40
static inline uint64_t
time_event(sycl::event& evt)
{
  // type aliasing because I wanted to keep them all single line
  using u64 = sycl::cl_ulong;
  using prof_t = sycl::info::event_profiling;

  const prof_t BEG = prof_t::command_start;
  const prof_t END = prof_t::command_end;

  const u64 beg = evt.get_profiling_info<BEG>();
  const u64 end = evt.get_profiling_info<END>();

  return static_cast<uint64_t>(end - beg);
}

// Convert how many bytes processed in how long timespan ( given in nanosecond
// level granularity ) to more human digestable
// format ( i.e. GB/ s or MB/ s or KB/ s or B/ s )
//
// Taken from
// https://github.com/itzmeanjan/acorn/blob/1982a24d69513cde6c4d74ee2ad2bd25745bd865/include/bench_utils.hpp#L42-L59
static inline const std::string
to_readable_bandwidth(const size_t bytes, // bytes
                      const uint64_t ts   // nanoseconds
)
{
  const double bytes_ = static_cast<double>(bytes);
  const double ts_ = static_cast<double>(ts) * 1e-9; // seconds
  const double bps = bytes_ / ts_;                   // bytes/ sec

  return bps >= GB   ? (std::to_string(bps / GB) + " GB/ s")
         : bps >= MB ? (std::to_string(bps / MB) + " MB/ s")
         : bps >= KB ? (std::to_string(bps / KB) + " KB/ s")
                     : (std::to_string(bps) + " B/ s");
}
