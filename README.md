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
Given N ( >= 0) -bytes input message, this algorithm computes 32 -bytes digest | Given 16 -bytes secret key, 16 -bytes public message nonce, N -bytes associated data & M -bytes plain text, encryption algorithm computes M -bytes cipher text & 16 -bytes authentication tag. After that using decryption algorithm, cipher text can be deciphered back to plain text along with a boolean verification flag. AEAD scheme provides secrecy only for plain text but authenticity, integrity for both plain(/cipher) text & associated data.
--- 

> There are two recommended versions of Photon-Beetle-AEAD, which are only different in their RATE length i.e. how many bytes are consumed in every iteration. Also note, Photon-Beetle-Hash has only one recommended variant, which consumes 32 -bits of input message in very iteration ( absorption phase ).

> For understanding what's AEAD, see [here](https://en.wikipedia.org/wiki/Authenticated_encryption)

> For checking what's happening on NIST LWC standardization effort, see [here](https://csrc.nist.gov/projects/lightweight-cryptography/finalists)

During this work, I followed Photon-Beetle specification, which was submitted to NIST LWC competition's final round call, see [this](https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/photon-beetle-spec-final.pdf). I suggest you go through that specification to get better understanding of Photon-Beetle-{Hash, AEAD}.

> I'm trying to keep this implementation as light weight as possible so that in a future date, it can easily be compiled down to GPU & FPGA executable, using SYCL, see [here](https://www.khronos.org/registry/SYCL/specs)

## Prerequisites

- C++ compiler such as `g++`/ `clang++`, with C++20 standard library

```bash
$ g++ --version
g++ (Ubuntu 11.2.0-19ubuntu1) 11.2.0
```

- System development utilities like `make`/ `cmake`

```bash
$ make --version
GNU Make 3.81

$ cmake --version
cmake version 3.23.2
```

- For testing functional correctness of Photon-Beetle implementation, you'll need `wget`, `unzip`, `python3`

```bash
$ python3 --version
Python 3.9.13
```

- Install `python3` dependencies by issuing

```bash
python3 -m pip install -r wrapper/python/requirements.txt --user
```

- For benchmarking implementation on CPU systems, you'll need to have `google-benchmark` library globally installed; see [here](https://github.com/google/benchmark/tree/60b16f1#installation) for guidance.

## Testing

For checking functional correctness of Photon-Beetle implementation, I use test vectors submitted with NIST LWC submission package. 

- For testing Photon-Beetle-Hash, I use same input bytes as provided in Known Answer Tests ( KATs ) & match computed digest(s) against provided ones.
- While for Photon-Beetle-AEAD, I'm using given secret key, nonce, associated data & plain text ( in KATs ) and computing cipher text, authentication tag. After that I also attempt to decrypt cipher text back to plain text while checking for truth value in verification flag.

> Consider taking a look at https://github.com/itzmeanjan/photon-beetle/commit/9d629e3 to understand why I've disable some assertions for Photon-Beetle-AEAD[128] implementation

For executing tests, issue

```bash
make
```

## Benchmarking

For benchmarking Photon-Beetle-{Hash, AEAD} on CPU based systems, issue

```bash
make benchmark
```

### On ARM Cortex-A72

```bash
2022-06-12T10:04:47+00:00
Running ./bench/a.out
Run on (16 X 166.66 MHz CPU s)
CPU Caches:
  L1 Data 32 KiB (x16)
  L1 Instruction 48 KiB (x16)
  L2 Unified 2048 KiB (x4)
Load Average: 1.00, 1.00, 1.00
--------------------------------------------------------------------------------------------------------
Benchmark                                              Time             CPU   Iterations UserCounters...
--------------------------------------------------------------------------------------------------------
bench_photon_beetle::permute                       70026 ns        70026 ns         9991 bytes_per_second=892.527k/s
bench_photon_beetle::hash/64                     1072538 ns      1072511 ns          653 bytes_per_second=58.2745k/s
bench_photon_beetle::hash/128                    2286740 ns      2286728 ns          306 bytes_per_second=54.6633k/s
bench_photon_beetle::hash/256                    4715922 ns      4715651 ns          148 bytes_per_second=53.015k/s
bench_photon_beetle::hash/512                    9572989 ns      9572725 ns           73 bytes_per_second=52.2317k/s
bench_photon_beetle::hash/1024                  19287349 ns     19287031 ns           36 bytes_per_second=51.8483k/s
bench_photon_beetle::hash/2048                  38717005 ns     38716358 ns           18 bytes_per_second=51.6578k/s
bench_photon_beetle::hash/4096                  77575346 ns     77574936 ns            9 bytes_per_second=51.563k/s
bench_photon_beetle::aead_encrypt<4>/32/64       1069205 ns      1069172 ns          655 bytes_per_second=87.6847k/s
bench_photon_beetle::aead_decrypt<4>/32/64       1035052 ns      1035029 ns          676 bytes_per_second=90.5772k/s
bench_photon_beetle::aead_encrypt<4>/32/128      1729416 ns      1729382 ns          405 bytes_per_second=90.3502k/s
bench_photon_beetle::aead_decrypt<4>/32/128      1673563 ns      1673494 ns          418 bytes_per_second=93.3676k/s
bench_photon_beetle::aead_encrypt<4>/32/256      3050140 ns      3049992 ns          230 bytes_per_second=92.2134k/s
bench_photon_beetle::aead_decrypt<4>/32/256      2949911 ns      2949855 ns          237 bytes_per_second=95.3437k/s
bench_photon_beetle::aead_encrypt<4>/32/512      5690871 ns      5690771 ns          123 bytes_per_second=93.3529k/s
bench_photon_beetle::aead_decrypt<4>/32/512      5503005 ns      5502970 ns          127 bytes_per_second=96.5388k/s
bench_photon_beetle::aead_encrypt<4>/32/1024    10974128 ns     10973948 ns           64 bytes_per_second=93.9726k/s
bench_photon_beetle::aead_decrypt<4>/32/1024    10609321 ns     10608931 ns           66 bytes_per_second=97.2058k/s
bench_photon_beetle::aead_encrypt<4>/32/2048    21536574 ns     21535999 ns           33 bytes_per_second=94.3188k/s
bench_photon_beetle::aead_decrypt<4>/32/2048    20821023 ns     20820636 ns           34 bytes_per_second=97.5595k/s
bench_photon_beetle::aead_encrypt<4>/32/4096    42661992 ns     42661732 ns           16 bytes_per_second=94.4933k/s
bench_photon_beetle::aead_decrypt<4>/32/4096    41245323 ns     41244561 ns           17 bytes_per_second=97.7402k/s
bench_photon_beetle::aead_encrypt<16>/32/64       349217 ns       349210 ns         2005 bytes_per_second=268.463k/s
bench_photon_beetle::aead_decrypt<16>/32/64       337525 ns       337517 ns         2074 bytes_per_second=277.764k/s
bench_photon_beetle::aead_encrypt<16>/32/128      546943 ns       546932 ns         1280 bytes_per_second=285.685k/s
bench_photon_beetle::aead_decrypt<16>/32/128      529817 ns       529780 ns         1321 bytes_per_second=294.933k/s
bench_photon_beetle::aead_encrypt<16>/32/256      942500 ns       942461 ns          743 bytes_per_second=298.421k/s
bench_photon_beetle::aead_decrypt<16>/32/256      914288 ns       914271 ns          766 bytes_per_second=307.622k/s
bench_photon_beetle::aead_encrypt<16>/32/512     1733450 ns      1733420 ns          404 bytes_per_second=306.475k/s
bench_photon_beetle::aead_decrypt<16>/32/512     1683282 ns      1683233 ns          416 bytes_per_second=315.613k/s
bench_photon_beetle::aead_encrypt<16>/32/1024    3315529 ns      3315469 ns          211 bytes_per_second=311.042k/s
bench_photon_beetle::aead_decrypt<16>/32/1024    3221270 ns      3221170 ns          217 bytes_per_second=320.148k/s
bench_photon_beetle::aead_encrypt<16>/32/2048    6479425 ns      6479311 ns          108 bytes_per_second=313.498k/s
bench_photon_beetle::aead_decrypt<16>/32/2048    6296967 ns      6296861 ns          111 bytes_per_second=322.581k/s
bench_photon_beetle::aead_encrypt<16>/32/4096   12807225 ns     12807043 ns           55 bytes_per_second=314.768k/s
bench_photon_beetle::aead_decrypt<16>/32/4096   12448009 ns     12447931 ns           56 bytes_per_second=323.849k/s
```

### On Intel(R) Core(TM) i5-8279U CPU @ 2.40GHz

```bash
2022-06-12T13:02:03+04:00
Running ./bench/a.out
Run on (8 X 2400 MHz CPU s)
CPU Caches:
  L1 Data 32 KiB
  L1 Instruction 32 KiB
  L2 Unified 256 KiB (x4)
  L3 Unified 6144 KiB
Load Average: 1.97, 2.26, 2.19
--------------------------------------------------------------------------------------------------------
Benchmark                                              Time             CPU   Iterations UserCounters...
--------------------------------------------------------------------------------------------------------
bench_photon_beetle::permute                       16080 ns        15806 ns        34762 bytes_per_second=3.86158M/s
bench_photon_beetle::hash/64                      216730 ns       215101 ns         3310 bytes_per_second=290.562k/s
bench_photon_beetle::hash/128                     459456 ns       456787 ns         1313 bytes_per_second=273.651k/s
bench_photon_beetle::hash/256                    1034570 ns      1017711 ns          734 bytes_per_second=245.649k/s
bench_photon_beetle::hash/512                    1950505 ns      1930603 ns          358 bytes_per_second=258.986k/s
bench_photon_beetle::hash/1024                   3984408 ns      3942440 ns          168 bytes_per_second=253.65k/s
bench_photon_beetle::hash/2048                   7808833 ns      7731894 ns           85 bytes_per_second=258.669k/s
bench_photon_beetle::hash/4096                  15401547 ns     15315600 ns           45 bytes_per_second=261.172k/s
bench_photon_beetle::aead_encrypt<4>/32/64        379162 ns       377042 ns         1864 bytes_per_second=248.646k/s
bench_photon_beetle::aead_decrypt<4>/32/64        377458 ns       375392 ns         1883 bytes_per_second=249.739k/s
bench_photon_beetle::aead_encrypt<4>/32/128       615026 ns       611800 ns         1093 bytes_per_second=255.394k/s
bench_photon_beetle::aead_decrypt<4>/32/128       620589 ns       617342 ns         1091 bytes_per_second=253.101k/s
bench_photon_beetle::aead_encrypt<4>/32/256      1093488 ns      1088329 ns          601 bytes_per_second=258.424k/s
bench_photon_beetle::aead_decrypt<4>/32/256      1115491 ns      1109951 ns          628 bytes_per_second=253.39k/s
bench_photon_beetle::aead_encrypt<4>/32/512      2052975 ns      2040974 ns          341 bytes_per_second=260.292k/s
bench_photon_beetle::aead_decrypt<4>/32/512      2064891 ns      2053332 ns          337 bytes_per_second=258.726k/s
bench_photon_beetle::aead_encrypt<4>/32/1024     3993247 ns      3973412 ns          177 bytes_per_second=259.538k/s
bench_photon_beetle::aead_decrypt<4>/32/1024     4011501 ns      3992333 ns          177 bytes_per_second=258.308k/s
bench_photon_beetle::aead_encrypt<4>/32/2048     8187158 ns      8069529 ns           85 bytes_per_second=251.719k/s
bench_photon_beetle::aead_decrypt<4>/32/2048     7864395 ns      7822124 ns           89 bytes_per_second=259.68k/s
bench_photon_beetle::aead_encrypt<4>/32/4096    16805254 ns     16555000 ns           45 bytes_per_second=243.506k/s
bench_photon_beetle::aead_decrypt<4>/32/4096    16141279 ns     15923045 ns           44 bytes_per_second=253.171k/s
bench_photon_beetle::aead_encrypt<16>/32/64       114112 ns       111700 ns         6131 bytes_per_second=839.3k/s
bench_photon_beetle::aead_decrypt<16>/32/64       110000 ns       108807 ns         6089 bytes_per_second=861.62k/s
bench_photon_beetle::aead_encrypt<16>/32/128      178991 ns       176469 ns         4033 bytes_per_second=885.425k/s
bench_photon_beetle::aead_decrypt<16>/32/128      169357 ns       168177 ns         4048 bytes_per_second=929.079k/s
bench_photon_beetle::aead_encrypt<16>/32/256      289668 ns       287966 ns         2371 bytes_per_second=976.678k/s
bench_photon_beetle::aead_decrypt<16>/32/256      301512 ns       298654 ns         2432 bytes_per_second=941.726k/s
bench_photon_beetle::aead_encrypt<16>/32/512      546452 ns       540784 ns         1224 bytes_per_second=982.369k/s
bench_photon_beetle::aead_decrypt<16>/32/512      531875 ns       529462 ns         1265 bytes_per_second=1003.38k/s
bench_photon_beetle::aead_encrypt<16>/32/1024    1014378 ns      1009668 ns          659 bytes_per_second=1021.38k/s
bench_photon_beetle::aead_decrypt<16>/32/1024    1069043 ns      1052839 ns          652 bytes_per_second=979.495k/s
bench_photon_beetle::aead_encrypt<16>/32/2048    2062620 ns      2036237 ns          334 bytes_per_second=997.551k/s
bench_photon_beetle::aead_decrypt<16>/32/2048    2104639 ns      2069352 ns          341 bytes_per_second=981.588k/s
bench_photon_beetle::aead_encrypt<16>/32/4096    3990795 ns      3956385 ns          174 bytes_per_second=1018.92k/s
bench_photon_beetle::aead_decrypt<16>/32/4096    4103685 ns      4065791 ns          172 bytes_per_second=991.505k/s
```
