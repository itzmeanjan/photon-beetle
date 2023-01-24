# photon-beetle
Photon-Beetle: Lightweight Authenticated Encryption &amp; Hashing 

## Overview

Photon-Beetle is the fifth NIST Light Weight Cryptography (LWC) competition's final round candidate, which I've decided to implement as a zero-dependency, easy to use, header-only C++ library. Using this library in your project should be as easy as just including proper header files ( see [below](#usage) for example ) & letting compiler know where to find these headers. Before this, I've worked on following implementations which are also competing in NIST LWC

- Ascon, see [here](https://github.com/itzmeanjan/ascon)
- TinyJambu, see [here](https://github.com/itzmeanjan/tinyjambu)
- Xoodyak, see [here](https://github.com/itzmeanjan/xoodyak)
- Sparkle, see [here](https://github.com/itzmeanjan/sparkle)

Here I'm maintaining recommended versions ( well parameters suggested in the specification document ) of both Photon-Beetle-Hash & Photon-Beetle-AEAD.

Photon-Beetle-Hash[32] | Photon-Beetle-AEAD[32, 128]
:-- | --:
Given N ( >= 0) -bytes input message, this algorithm computes 32 -bytes digest | Given 16 -bytes secret key, 16 -bytes public message nonce, N ( >=0 ) -bytes associated data & M ( >=0 ) -bytes plain text, encryption algorithm computes M ( >=0 ) -bytes cipher text & 16 -bytes authentication tag. After that using decryption algorithm, cipher text can be deciphered back to plain text along with a boolean verification flag. AEAD scheme provides secrecy only for plain text but authenticity, integrity for both plain(/cipher) text & associated data. In case of failure in tag verification, unverified plain text is never released - it's zeroed.
--- 

> **Note** Associated data is never encrypted by this AEAD scheme.

> **Note** There are two recommended versions of Photon-Beetle-AEAD, which are only different in their RATE length i.e. how many bytes are consumed in every iteration. Rate can be either 4 -bytes or 16 -bytes. And as expected, Photon-Beetle-AEAD[128], which uses 16 -bytes rate, it much faster ( to encrypt/ decrypt ) compared to Photon-Beetle-AEAD[32] ∀ messages of length >= 64B. Also note, Photon-Beetle-Hash has only one recommended variant, which consumes 32 -bits of input message in every iteration ( absorption phase ).

> **Note** For understanding what's AEAD, see [here](https://en.wikipedia.org/wiki/Authenticated_encryption)

> **Note** For checking progress of NIST LWC standardization effort, see [here](https://csrc.nist.gov/projects/lightweight-cryptography/finalists)

During this work, I followed Photon-Beetle specification, which was submitted to NIST LWC competition's final round call, see [this](https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/photon-beetle-spec-final.pdf). I suggest you go through that specification to get better understanding of Photon-Beetle-{Hash, AEAD}.

## Prerequisites

- C++ compiler such as `g++`/ `clang++`, with C++20 standard library

```fish
$ g++ --version
g++ (Homebrew GCC 12.2.0) 12.2.0

$ clang++ --version
Apple clang version 14.0.0 (clang-1400.0.29.202)
Target: x86_64-apple-darwin22.2.0
Thread model: posix
InstalledDir: /Library/Developer/CommandLineTools/usr/bin
```

- System development utilities like `make`, `cmake` and `git` is required. While `python3`, `unzip` and `wget` is also required for testing.

```fish
$ make --version
GNU Make 3.81

$ cmake --version
cmake version 3.23.2

$ python3 --version
Python 3.10.9

$ git --version
git version 2.39.1

$ unzip -v
UnZip 6.00 of 20 April 2009, by Info-ZIP.

$ wget --version
GNU Wget 1.21.3 built on darwin22.1.0.
```

- Install `python3` dependencies by issuing

```fish
python3 -m pip install -r wrapper/python/requirements.txt --user
```

- For benchmarking implementation on CPU systems, you'll need to have `google-benchmark` library globally installed; see [here](https://github.com/google/benchmark/tree/60b16f1#installation) for guidance.

## Testing

For checking functional correctness & conformance with Photon-Beetle specification, I use test vectors submitted with NIST LWC submission package.

- For testing Photon-Beetle-Hash, I use same input bytes as provided in Known Answer Tests ( KATs ) & match computed digest(s) against provided ones.
- While for Photon-Beetle-AEAD, I'm using given secret key, nonce, associated data & plain text ( in KATs ) and computing cipher text, authentication tag. After that I also attempt to decrypt cipher text back to plain text while checking for truth value in verification flag. Finally to ensure conformance, I make sure to check both computed cipher text and authentication tag with given ones in test vectors.

For executing tests, issue

```fish
make
```

## Benchmarking

For benchmarking Photon-Beetle-{Hash, AEAD} on CPU based systems, issue

> **Warning** If your CPU has scaling enabled, you may want to disable that, see [this](https://github.com/google/benchmark/blob/60b16f1/docs/user_guide.md#disabling-cpu-frequency-scaling) guide.

```fish
make benchmark
```

### On Intel(R) Core(TM) i5-8279U CPU @ 2.40GHz ( when compiled with Clang )

```fish
2023-01-24T09:50:12+04:00
Running ./bench/a.out
Run on (8 X 2400 MHz CPU s)
CPU Caches:
  L1 Data 32 KiB
  L1 Instruction 32 KiB
  L2 Unified 256 KiB (x4)
  L3 Unified 6144 KiB
Load Average: 3.44, 1.95, 1.77
--------------------------------------------------------------------------------------------------------
Benchmark                                              Time             CPU   Iterations UserCounters...
--------------------------------------------------------------------------------------------------------
bench_photon_beetle::permute                        1666 ns         1666 ns       408993 bytes_per_second=18.3227M/s
bench_photon_beetle::hash/64                       23556 ns        23528 ns        29473 bytes_per_second=2.5941M/s
bench_photon_beetle::hash/128                      50279 ns        50231 ns        13610 bytes_per_second=2.43019M/s
bench_photon_beetle::hash/256                     104574 ns       104448 ns         6560 bytes_per_second=2.33744M/s
bench_photon_beetle::hash/512                     211898 ns       211696 ns         3263 bytes_per_second=2.30652M/s
bench_photon_beetle::hash/1024                    425005 ns       424698 ns         1651 bytes_per_second=2.29943M/s
bench_photon_beetle::hash/2048                    852470 ns       851860 ns          809 bytes_per_second=2.29278M/s
bench_photon_beetle::hash/4096                   1710867 ns      1709895 ns          401 bytes_per_second=2.2845M/s
bench_photon_beetle::aead_encrypt<4>/32/64         42109 ns        42080 ns        16625 bytes_per_second=2.17567M/s
bench_photon_beetle::aead_decrypt<4>/32/64         42104 ns        42074 ns        16478 bytes_per_second=2.17599M/s
bench_photon_beetle::aead_encrypt<4>/32/128        68877 ns        68852 ns         9828 bytes_per_second=2.21618M/s
bench_photon_beetle::aead_decrypt<4>/32/128        68969 ns        68916 ns         9939 bytes_per_second=2.21411M/s
bench_photon_beetle::aead_encrypt<4>/32/256       122876 ns       122798 ns         5606 bytes_per_second=2.23668M/s
bench_photon_beetle::aead_decrypt<4>/32/256       123093 ns       123030 ns         5587 bytes_per_second=2.23246M/s
bench_photon_beetle::aead_encrypt<4>/32/512       231254 ns       231118 ns         3006 bytes_per_second=2.24473M/s
bench_photon_beetle::aead_decrypt<4>/32/512       230867 ns       230697 ns         3004 bytes_per_second=2.24883M/s
bench_photon_beetle::aead_encrypt<4>/32/1024      445609 ns       445322 ns         1566 bytes_per_second=2.26146M/s
bench_photon_beetle::aead_decrypt<4>/32/1024      446978 ns       446517 ns         1568 bytes_per_second=2.25541M/s
bench_photon_beetle::aead_encrypt<4>/32/2048      880889 ns       880030 ns          787 bytes_per_second=2.25406M/s
bench_photon_beetle::aead_decrypt<4>/32/2048      885183 ns       884297 ns          788 bytes_per_second=2.24319M/s
bench_photon_beetle::aead_encrypt<4>/32/4096     1740720 ns      1739594 ns          399 bytes_per_second=2.26304M/s
bench_photon_beetle::aead_decrypt<4>/32/4096     1736518 ns      1735345 ns          374 bytes_per_second=2.26858M/s
bench_photon_beetle::aead_encrypt<16>/32/64        11796 ns        11790 ns        58526 bytes_per_second=7.76524M/s
bench_photon_beetle::aead_decrypt<16>/32/64        11886 ns        11878 ns        58707 bytes_per_second=7.70779M/s
bench_photon_beetle::aead_encrypt<16>/32/128       18812 ns        18779 ns        37364 bytes_per_second=8.12566M/s
bench_photon_beetle::aead_decrypt<16>/32/128       18729 ns        18717 ns        37431 bytes_per_second=8.15257M/s
bench_photon_beetle::aead_encrypt<16>/32/256       32132 ns        32105 ns        21607 bytes_per_second=8.55491M/s
bench_photon_beetle::aead_decrypt<16>/32/256       32065 ns        32052 ns        21641 bytes_per_second=8.5692M/s
bench_photon_beetle::aead_encrypt<16>/32/512       59252 ns        59177 ns        11386 bytes_per_second=8.76696M/s
bench_photon_beetle::aead_decrypt<16>/32/512       59209 ns        59178 ns        11502 bytes_per_second=8.76679M/s
bench_photon_beetle::aead_encrypt<16>/32/1024     114003 ns       113901 ns         6112 bytes_per_second=8.84171M/s
bench_photon_beetle::aead_decrypt<16>/32/1024     113694 ns       113622 ns         5924 bytes_per_second=8.86342M/s
bench_photon_beetle::aead_encrypt<16>/32/2048     221617 ns       221503 ns         3106 bytes_per_second=8.95537M/s
bench_photon_beetle::aead_decrypt<16>/32/2048     221757 ns       221580 ns         3129 bytes_per_second=8.95227M/s
bench_photon_beetle::aead_encrypt<16>/32/4096     437064 ns       436821 ns         1595 bytes_per_second=9.01231M/s
bench_photon_beetle::aead_decrypt<16>/32/4096     440065 ns       439724 ns         1589 bytes_per_second=8.95281M/s
```

## Usage

Using Photon-Beetle C++ API is as easy as including proper header files & letting compiler know where it can find these header files, which is `./include` directory.

If you're only interested in Photon-Beetle-Hash implementation, consider importing [`include/hash.hpp`](./include/hash.hpp) in your project, while for Photon-Beetle-AEAD include [`include/aead.hpp`](./include/aead.hpp). Or you may just include [`./include/photon_beetle.hpp`](./include/photon_beetle.hpp) which has both hashing and aead headers included.

> **Note** Photon-Beetle-Hash produces 32 -bytes digest, given N -bytes input message | N >= 0.

You may note, Photon-Beetle-AEAD routines i.e. encrypt/ decrypt take a template parameter called **RATE**, which can ∈ {4, 16}. If you want to use Photon-Beetle-AEAD-32 variant, which consumes 4 -bytes of message/ associated data in every iteration, ensure that you set **RATE = 4**. When interested in using Photon-Beetle-AEAD-128, set **RATE = 16**, so that permutation state can consume 16 -bytes of message/ associated data per iteration.

> **Note** For both Photon-Beetle-AEAD-32 & Photon-Beetle-AEAD-128, secret key/ public message nonce/ authentication tag is of byte length 16.

I've written two examples demonstrating usage of Photon-Beetle-{Hash, AEAD} API.

- For Photon-Beetle-Hash, see [here](./example/hash.cpp)
- For Photon-Beetle-AEAD-{32,128}, see [here](./example/aead.cpp)

```fish
# Hashing
$ clang++ -std=c++20 -Wall -O3 -march=native -I ./include example/hash.cpp && ./a.out
Input   : 5b862b2329ae543686c8eb8e263647da2598e84fc87a24499c7cfd35414cd96bf7ea077676ea9687f48267c657514f2caa41ba8b5c594d68f67159941f892c82
Output  : c323f4d9baf3c5d861eaa25738670896392075bf87d40dcf54823fe4ff8ea9f1

# --- --- --- --- ---

# AEAD
$ clang++ -std=c++20 -Wall -O3 -march=native -I ./include example/aead.cpp && ./a.out
Key      : 461060a398b812e0659630d4eee673c2
Nonce    : 6dbc941e6ccedb48e6eb994bfb08cd5e
Data     : 894f0077bf8bcb818cbcb9e1b6eea1223dd8e5ba3a5a467f1c4c2d337b6435d2
Text     : e23c22b545a707c27be9c97db6669b4b3c5d0687cabc13c78f836d810ce010bc30f69587dcb40a9ce609b59ec75c63954284d47b5fb9c83c013b92ff5b7343f6
Tag      : de69da70bffa6f6b2da38af8ea1b2544
Cipher   : 908c82cc001bf8b69389b9db1cbddc630b79a59b25c4afa9ca163f3f3ffa5e2611ee4fd8eb47ff6feb28893ed08f7bd377cb21c129b9685f733f7149d0e22375
Decrypted: e23c22b545a707c27be9c97db6669b4b3c5d0687cabc13c78f836d810ce010bc30f69587dcb40a9ce609b59ec75c63954284d47b5fb9c83c013b92ff5b7343f6
```
