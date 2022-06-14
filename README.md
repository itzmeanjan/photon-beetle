# photon-beetle
Photon-Beetle: Lightweight Authenticated Encryption &amp; Hashing 

## Overview

Photon-Beetle is the fifth NIST Light Weight Cryptography (LWC) competition's final round candidate, which I've decided to implement as a zero-dependency, easy to use, header-only C++ library. Using this library in your project should be as easy as just including proper header files ( see below for example ) & letting compiler know where to find these headers. Before this, I've worked on following implementations

- Ascon, see [here](https://github.com/itzmeanjan/ascon)
- TinyJambu, see [here](https://github.com/itzmeanjan/tinyjambu)
- Xoodyak, see [here](https://github.com/itzmeanjan/xoodyak)
- Sparkle, see [here](https://github.com/itzmeanjan/sparkle)

Here I'm keeping recommended versions of both Photon-Beetle-Hash & Photon-Beetle-AEAD.

Photon-Beetle-Hash[32] | Photon-Beetle-AEAD[32, 128]
--- | ---
Given N ( >= 0) -bytes input message, this algorithm computes 32 -bytes digest | Given 16 -bytes secret key, 16 -bytes public message nonce, N ( >=0 ) -bytes associated data & M ( >=0 ) -bytes plain text, encryption algorithm computes M ( >=0 ) -bytes cipher text & 16 -bytes authentication tag. After that using decryption algorithm, cipher text can be deciphered back to plain text along with a boolean verification flag. AEAD scheme provides secrecy only for plain text but authenticity, integrity for both plain(/cipher) text & associated data.
--- 

> Note, associated data is never encrypted.

> There are two recommended versions of Photon-Beetle-AEAD, which are only different in their RATE length i.e. how many bytes are consumed in every iteration. Also note, Photon-Beetle-Hash has only one recommended variant, which consumes 32 -bits of input message in every iteration ( absorption phase ).

> For understanding what's AEAD, see [here](https://en.wikipedia.org/wiki/Authenticated_encryption)

> For checking what's happening on NIST LWC standardization effort, see [here](https://csrc.nist.gov/projects/lightweight-cryptography/finalists)

During this work, I followed Photon-Beetle specification, which was submitted to NIST LWC competition's final round call, see [this](https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/photon-beetle-spec-final.pdf). I suggest you go through that specification to get better understanding of Photon-Beetle-{Hash, AEAD}.

> I'm trying to keep this implementation as light weight as possible so that in a future date, it can easily be compiled down to GPU & FPGA executable, using SYCL, see [here](https://www.khronos.org/registry/SYCL/specs)

## Prerequisites

- C++ compiler such as `g++`/ `clang++`, with C++20 standard library

```fish
$ g++ --version
g++ (Ubuntu 11.2.0-19ubuntu1) 11.2.0
```

- System development utilities like `make`/ `cmake`

```fish
$ make --version
GNU Make 3.81

$ cmake --version
cmake version 3.23.2
```

- For testing functional correctness of Photon-Beetle implementation, you'll need `wget`, `unzip`, `python3`

```fish
$ python3 --version
Python 3.9.13
```

- Install `python3` dependencies by issuing

```fish
python3 -m pip install -r wrapper/python/requirements.txt --user
```

- For benchmarking implementation on CPU systems, you'll need to have `google-benchmark` library globally installed; see [here](https://github.com/google/benchmark/tree/60b16f1#installation) for guidance.

## Testing

For checking functional correctness & conformance with standard of Photon-Beetle implementation, I use test vectors submitted with NIST LWC submission package.

- For testing Photon-Beetle-Hash, I use same input bytes as provided in Known Answer Tests ( KATs ) & match computed digest(s) against provided ones.
- While for Photon-Beetle-AEAD, I'm using given secret key, nonce, associated data & plain text ( in KATs ) and computing cipher text, authentication tag. After that I also attempt to decrypt cipher text back to plain text while checking for truth value in verification flag. Finally to ensure conformance, I make sure to check both computed cipher text and authentication tag with given ones in test vectors.

For executing tests, issue

```fish
make
```

## Benchmarking

For benchmarking Photon-Beetle-{Hash, AEAD} on CPU based systems, issue

> If your CPU has scaling enabled, you may want to disable that, see [this](https://github.com/google/benchmark/blob/60b16f1/docs/user_guide.md#disabling-cpu-frequency-scaling) guide.

```fish
make benchmark
```

### On ARM Cortex-A72

```fish
2022-06-14T13:45:56+00:00
Running ./bench/a.out
Run on (16 X 166.66 MHz CPU s)
CPU Caches:
  L1 Data 32 KiB (x16)
  L1 Instruction 48 KiB (x16)
  L2 Unified 2048 KiB (x4)
Load Average: 0.32, 0.09, 0.03
--------------------------------------------------------------------------------------------------------
Benchmark                                              Time             CPU   Iterations UserCounters...
--------------------------------------------------------------------------------------------------------
bench_photon_beetle::permute                       41240 ns        41239 ns        16974 bytes_per_second=1.48003M/s
bench_photon_beetle::hash/64                      572806 ns       572802 ns         1223 bytes_per_second=109.113k/s
bench_photon_beetle::hash/128                    1225497 ns      1225460 ns          572 bytes_per_second=102.003k/s
bench_photon_beetle::hash/256                    2528992 ns      2528977 ns          277 bytes_per_second=98.8542k/s
bench_photon_beetle::hash/512                    5138365 ns      5138283 ns          136 bytes_per_second=97.3088k/s
bench_photon_beetle::hash/1024                  10358199 ns     10357745 ns           68 bytes_per_second=96.5461k/s
bench_photon_beetle::hash/2048                  20789030 ns     20788897 ns           34 bytes_per_second=96.2052k/s
bench_photon_beetle::hash/4096                  41666339 ns     41664427 ns           17 bytes_per_second=96.0052k/s
bench_photon_beetle::aead_encrypt<4>/32/64       1040025 ns      1040018 ns          674 bytes_per_second=90.1427k/s
bench_photon_beetle::aead_decrypt<4>/32/64       1041379 ns      1041317 ns          672 bytes_per_second=90.0302k/s
bench_photon_beetle::aead_encrypt<4>/32/128      1705724 ns      1705715 ns          410 bytes_per_second=91.6038k/s
bench_photon_beetle::aead_decrypt<4>/32/128      1707768 ns      1707699 ns          410 bytes_per_second=91.4974k/s
bench_photon_beetle::aead_encrypt<4>/32/256      3037932 ns      3037912 ns          230 bytes_per_second=92.58k/s
bench_photon_beetle::aead_decrypt<4>/32/256      3042767 ns      3042706 ns          230 bytes_per_second=92.4342k/s
bench_photon_beetle::aead_encrypt<4>/32/512      5702385 ns      5702348 ns          123 bytes_per_second=93.1634k/s
bench_photon_beetle::aead_decrypt<4>/32/512      5707976 ns      5707940 ns          123 bytes_per_second=93.0721k/s
bench_photon_beetle::aead_encrypt<4>/32/1024    11030379 ns     11029936 ns           63 bytes_per_second=93.4956k/s
bench_photon_beetle::aead_decrypt<4>/32/1024    11043162 ns     11042810 ns           63 bytes_per_second=93.3866k/s
bench_photon_beetle::aead_encrypt<4>/32/2048    21683863 ns     21682795 ns           32 bytes_per_second=93.6803k/s
bench_photon_beetle::aead_decrypt<4>/32/2048    21713885 ns     21713739 ns           32 bytes_per_second=93.5468k/s
bench_photon_beetle::aead_encrypt<4>/32/4096    42992599 ns     42991801 ns           16 bytes_per_second=93.7679k/s
bench_photon_beetle::aead_decrypt<4>/32/4096    43047144 ns     43046236 ns           16 bytes_per_second=93.6493k/s
bench_photon_beetle::aead_encrypt<16>/32/64       292076 ns       292075 ns         2396 bytes_per_second=320.98k/s
bench_photon_beetle::aead_decrypt<16>/32/64       292228 ns       292220 ns         2400 bytes_per_second=320.82k/s
bench_photon_beetle::aead_encrypt<16>/32/128      458741 ns       458738 ns         1526 bytes_per_second=340.609k/s
bench_photon_beetle::aead_decrypt<16>/32/128      459239 ns       459225 ns         1524 bytes_per_second=340.247k/s
bench_photon_beetle::aead_encrypt<16>/32/256      792274 ns       792268 ns          883 bytes_per_second=354.993k/s
bench_photon_beetle::aead_decrypt<16>/32/256      792727 ns       792688 ns          883 bytes_per_second=354.805k/s
bench_photon_beetle::aead_encrypt<16>/32/512     1459572 ns      1459544 ns          479 bytes_per_second=363.984k/s
bench_photon_beetle::aead_decrypt<16>/32/512     1460618 ns      1460608 ns          479 bytes_per_second=363.718k/s
bench_photon_beetle::aead_encrypt<16>/32/1024    2795481 ns      2795427 ns          250 bytes_per_second=368.906k/s
bench_photon_beetle::aead_decrypt<16>/32/1024    2797380 ns      2797362 ns          250 bytes_per_second=368.651k/s
bench_photon_beetle::aead_encrypt<16>/32/2048    5468937 ns      5468837 ns          128 bytes_per_second=371.423k/s
bench_photon_beetle::aead_decrypt<16>/32/2048    5466611 ns      5466575 ns          128 bytes_per_second=371.576k/s
bench_photon_beetle::aead_encrypt<16>/32/4096   10810659 ns     10810206 ns           65 bytes_per_second=372.911k/s
bench_photon_beetle::aead_decrypt<16>/32/4096   10812616 ns     10812550 ns           65 bytes_per_second=372.831k/s
```

### On Intel(R) Core(TM) i5-8279U CPU @ 2.40GHz

```fish
2022-06-14T17:43:53+04:00
Running ./bench/a.out
Run on (8 X 2400 MHz CPU s)
CPU Caches:
  L1 Data 32 KiB
  L1 Instruction 32 KiB
  L2 Unified 256 KiB (x4)
  L3 Unified 6144 KiB
Load Average: 2.35, 1.89, 1.82
--------------------------------------------------------------------------------------------------------
Benchmark                                              Time             CPU   Iterations UserCounters...
--------------------------------------------------------------------------------------------------------
bench_photon_beetle::permute                       15226 ns        15099 ns        46159 bytes_per_second=4.04227M/s
bench_photon_beetle::hash/64                      222837 ns       219609 ns         3236 bytes_per_second=284.597k/s
bench_photon_beetle::hash/128                     470816 ns       464823 ns         1487 bytes_per_second=268.919k/s
bench_photon_beetle::hash/256                     998974 ns       982943 ns          743 bytes_per_second=254.338k/s
bench_photon_beetle::hash/512                    1914557 ns      1898967 ns          367 bytes_per_second=263.301k/s
bench_photon_beetle::hash/1024                   3781286 ns      3761283 ns          180 bytes_per_second=265.867k/s
bench_photon_beetle::hash/2048                   7849538 ns      7767326 ns           92 bytes_per_second=257.489k/s
bench_photon_beetle::hash/4096                  16254025 ns     16023618 ns           34 bytes_per_second=249.632k/s
bench_photon_beetle::aead_encrypt<4>/32/64        393079 ns       387664 ns         1880 bytes_per_second=241.833k/s
bench_photon_beetle::aead_decrypt<4>/32/64        382187 ns       378475 ns         1729 bytes_per_second=247.704k/s
bench_photon_beetle::aead_encrypt<4>/32/128       670910 ns       657634 ns          988 bytes_per_second=237.594k/s
bench_photon_beetle::aead_decrypt<4>/32/128       607051 ns       603922 ns         1122 bytes_per_second=258.726k/s
bench_photon_beetle::aead_encrypt<4>/32/256      1142099 ns      1127174 ns          637 bytes_per_second=249.518k/s
bench_photon_beetle::aead_decrypt<4>/32/256      1144226 ns      1130141 ns          625 bytes_per_second=248.863k/s
bench_photon_beetle::aead_encrypt<4>/32/512      2422600 ns      2359501 ns          337 bytes_per_second=225.153k/s
bench_photon_beetle::aead_decrypt<4>/32/512      2038698 ns      2028170 ns          342 bytes_per_second=261.936k/s
bench_photon_beetle::aead_encrypt<4>/32/1024     3968146 ns      3943539 ns          178 bytes_per_second=261.504k/s
bench_photon_beetle::aead_decrypt<4>/32/1024     3921783 ns      3900844 ns          179 bytes_per_second=264.366k/s
bench_photon_beetle::aead_encrypt<4>/32/2048     7728110 ns      7685461 ns           89 bytes_per_second=264.298k/s
bench_photon_beetle::aead_decrypt<4>/32/2048     7733825 ns      7695753 ns           89 bytes_per_second=263.944k/s
bench_photon_beetle::aead_encrypt<4>/32/4096    15255245 ns     15171682 ns           44 bytes_per_second=265.709k/s
bench_photon_beetle::aead_decrypt<4>/32/4096    15348496 ns     15251326 ns           46 bytes_per_second=264.321k/s
bench_photon_beetle::aead_encrypt<16>/32/64       104515 ns       103927 ns         6654 bytes_per_second=902.072k/s
bench_photon_beetle::aead_decrypt<16>/32/64       104149 ns       103555 ns         6587 bytes_per_second=905.32k/s
bench_photon_beetle::aead_encrypt<16>/32/128      165879 ns       164753 ns         4238 bytes_per_second=948.391k/s
bench_photon_beetle::aead_decrypt<16>/32/128      164031 ns       162965 ns         4234 bytes_per_second=958.797k/s
bench_photon_beetle::aead_encrypt<16>/32/256      283887 ns       282271 ns         2482 bytes_per_second=996.382k/s
bench_photon_beetle::aead_decrypt<16>/32/256      282412 ns       280767 ns         2468 bytes_per_second=1001.72k/s
bench_photon_beetle::aead_encrypt<16>/32/512      517260 ns       514298 ns         1325 bytes_per_second=1032.96k/s
bench_photon_beetle::aead_decrypt<16>/32/512      520527 ns       517884 ns         1264 bytes_per_second=1025.81k/s
bench_photon_beetle::aead_encrypt<16>/32/1024    1001690 ns       996538 ns          692 bytes_per_second=1034.83k/s
bench_photon_beetle::aead_decrypt<16>/32/1024     995399 ns       989455 ns          692 bytes_per_second=1042.24k/s
bench_photon_beetle::aead_encrypt<16>/32/2048    1944561 ns      1932047 ns          358 bytes_per_second=1051.35k/s
bench_photon_beetle::aead_decrypt<16>/32/2048    1945304 ns      1934639 ns          363 bytes_per_second=1049.94k/s
bench_photon_beetle::aead_encrypt<16>/32/4096    3826353 ns      3804654 ns          182 bytes_per_second=1059.56k/s
bench_photon_beetle::aead_decrypt<16>/32/4096    3854085 ns      3831663 ns          184 bytes_per_second=1052.09k/s
```

## Usage

Using Photon-Beetle C++ API is as easy as including proper header files & letting compiler know where it can find these header files, which is `./include` directory.

If you're interested in Photon-Beetle-Hash implementation, consider importing `include/hash.hpp` in your project, while for Photon-Beetle-AEAD include `include/aead.hpp`.

> Note, Photon-Beetle-Hash produces 32 -bytes digest of N -bytes input message | N >= 0.

You may note, Photon-Beetle-AEAD routines i.e. encrypt/ decrypt take a template parameter called **RATE**, which can ∈ {4, 16}. If you want to use Photon-Beetle-AEAD-32 variant, which consumes 4 -bytes of message/ associated data in every iteration, ensure that you set `RATE = 4`. When interested in using Photon-Beetle-AEAD-128, set `RATE = 16`, so that permutation state can consume 16 -bytes of message/ associated data per iteration.

> Note, for both Photon-Beetle-AEAD-32 & Photon-Beetle-AEAD-128, secret key/ public message nonce/ authentication tag is of byte length 16.

I've written two examples demonstrating usage of Photon-Beetle-{Hash, AEAD} API.

- For Photon-Beetle-Hash, see [here](https://github.com/itzmeanjan/photon-beetle/blob/618abea/example/hash.cpp)
- For Photon-Beetle-AEAD-{32,128}, see [here](https://github.com/itzmeanjan/photon-beetle/blob/618abea/example/aead.cpp)
