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
