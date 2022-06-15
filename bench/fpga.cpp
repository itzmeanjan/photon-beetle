#include "bench_fpga_hash.hpp"
#include "table.hpp"
#include <iostream>
#include <sycl/ext/intel/fpga_extensions.hpp>

#if !(defined FPGA_EMU || defined FPGA_HW)
#define FPGA_EMU
#endif

int
main()
{
  constexpr size_t min_wi_cnt = 1ul << 16;
  constexpr size_t max_wi_cnt = 1ul << 18;
  constexpr size_t min_mlen = 64ul;   // bytes
  constexpr size_t max_mlen = 4096ul; // bytes

#if defined FPGA_EMU
  sycl::ext::intel::fpga_emulator_selector s{};
#elif defined FPGA_HW
  sycl::ext::intel::fpga_selector s{};
#endif

  sycl::device d{ s };
  sycl::context c{ d };
  sycl::queue q{ c, d, sycl::property::queue::enable_profiling{} };

  std::cout << "Offloading to " << d.get_info<sycl::info::device::name>()
            << std::endl
            << std::endl;

  uint64_t* ts = static_cast<uint64_t*>(std::malloc(sizeof(uint64_t) * 3));
  size_t* io = static_cast<size_t*>(std::malloc(sizeof(size_t) * 3));

  std::cout << "Benchmarking Photon-Beetle-Hash" << std::endl << std::endl;

  TextTable t0('-', '|', '+');

  t0.add("invocation count");
  t0.add("message len ( bytes )");
  t0.add("host-to-device b/w");
  t0.add("kernel b/w");
  t0.add("device-to-host b/w");
  t0.endOfRow();

  for (size_t wi_cnt = min_wi_cnt; wi_cnt <= max_wi_cnt; wi_cnt <<= 1) {
    for (size_t mlen = min_mlen; mlen <= max_mlen; mlen <<= 1) {
      bench_photon_beetle_hash_fpga(q, mlen, wi_cnt, ts, io);

      t0.add(std::to_string(wi_cnt));
      t0.add(std::to_string(mlen));
      t0.add(to_readable_bandwidth(io[0], ts[0]));
      t0.add(to_readable_bandwidth(io[1], ts[1]));
      t0.add(to_readable_bandwidth(io[2], ts[2]));
      t0.endOfRow();
    }
  }

  t0.setAlignment(1, TextTable::Alignment::RIGHT);
  t0.setAlignment(2, TextTable::Alignment::RIGHT);
  t0.setAlignment(3, TextTable::Alignment::RIGHT);
  t0.setAlignment(4, TextTable::Alignment::RIGHT);
  t0.setAlignment(5, TextTable::Alignment::RIGHT);
  std::cout << t0;

  std::free(ts);
  std::free(io);

  return EXIT_SUCCESS;
}
