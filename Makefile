CXX = g++
CXXFLAGS = -std=c++20 -Wall -Wextra -pedantic
OPTFLAGS = -O3
IFLAGS = -I ./include

# Actually compiled code to be executed on host CPU, to be used only for testing functional correctness
FPGA_EMU_FLAGS = -DFPGA_EMU -fintelfpga

# Another option is using `intel_s10sx_pac:pac_s10` as FPGA board and if you do so ensure that
# on Intel Devcloud you use `fpga_runtime:stratix10` as offload target
#
# Otherwise if you stick to Arria 10 board, consider offloading to `fpga_runtime:arria10` attached VMs
# on Intel Devcloud ( default target board used in this project )
FPGA_OPT_FLAGS = -DFPGA_HW -fintelfpga -fsycl-link=early -Xshardware -Xsboard=intel_a10gx_pac:pac_a10

# Consider enabing -Xsprofile, when generating h/w image, so that execution can be profiled
# using Intel Vtune
#
# Consider reading 👆 note ( on top of `FPGA_OPT_FLAGS` definition ) for changing target board
FPGA_HW_FLAGS = -DFPGA_HW -fintelfpga -Xshardware -Xsboard=intel_a10gx_pac:pac_a10

all: test_kat

lib:
	$(CXX) $(CXXFLAGS) $(OPTFLAGS) $(IFLAGS) -I . -fPIC --shared wrapper/photon-beetle.cpp -o wrapper/libphoton-beetle.so

clean:
	find . -name '*.out' -o -name '*.o' -o -name '*.so' -o -name '*.gch' | xargs rm -rf

format:
	find . -name '*.cpp' -o -name '*.hpp' | xargs clang-format -i --style=Mozilla

test_kat:
	bash test_kat.sh

bench/a.out: bench/cpu.cpp include/*.hpp
	# make sure you've google-benchmark globally installed;
	# see https://github.com/google/benchmark/tree/60b16f1#installation
	$(CXX) $(CXXFLAGS) $(OPTFLAGS) $(IFLAGS) $< -lbenchmark -o $@

benchmark: bench/a.out
	./$<

# FPGA Emulation on CPU
bench/fpga_emu_bench.out: bench/fpga.cpp include/*.hpp
	dpcpp $(CXXFLAGS) $(FPGA_EMU_FLAGS) $(OPTFLAGS) $(IFLAGS) $< -o $@

fpga_emu_bench: bench/fpga_emu_bench.out
	./$<

# FPGA optimization report generation
fpga_opt_bench: bench/fpga.cpp include/*.hpp
	# output not supposed to be executed, instead consume report generated
	# inside `bench/fpga_opt_bench.prj/reports/` diretory
	dpcpp $(CXXFLAGS) $(FPGA_OPT_FLAGS) $(OPTFLAGS) $(IFLAGS) $< -o bench/$@.a

# FPGA h/w synthesis & benchmark
bench/fpga_hw_bench.out: bench/fpga.cpp include/*.hpp
	dpcpp $(CXXFLAGS) $(FPGA_HW_FLAGS) $(OPTFLAGS) $(IFLAGS) -reuse-exe=$@ $< -o $@

fpga_hw_bench: bench/fpga_hw_bench.out
	./$<
