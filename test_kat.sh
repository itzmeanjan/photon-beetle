#!/bin/bash

# Script for ease of execution of Known Answer Tests against Photon-Beetle implementation

# generate shared library object
make lib

# ---

mkdir -p tmp
pushd tmp

# download compressed NIST LWC submission of Photon-Beetle
wget -O photon-beetle.zip https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-submissions/photon-beetle.zip
# uncomress
unzip photon-beetle.zip

# copy Known Answer Tests outside of uncompressed NIST LWC submission directory
cp photon-beetle/Implementations/crypto_hash/photonbeetlehash256rate32v1/LWC_HASH_KAT_256.txt ../
cp photon-beetle/Implementations/crypto_aead/photonbeetleaead128rate32v1/LWC_AEAD_KAT_128_128.txt ../LWC_AEAD_KAT_128_128.txt.32
cp photon-beetle/Implementations/crypto_aead/photonbeetleaead128rate128v1/LWC_AEAD_KAT_128_128.txt ../LWC_AEAD_KAT_128_128.txt.128

popd

# ---

# remove NIST LWC submission zip
rm -rf tmp

# ---

pushd wrapper/python

# run tests
mv ../../LWC_HASH_KAT_256.txt .
python3 -m pytest -k hash_kat --cache-clear -v

mv ../../LWC_AEAD_KAT_128_128.txt.32 LWC_AEAD_KAT_128_128.txt
python3 -m pytest -k aead_32_kat --cache-clear -v

mv ../../LWC_AEAD_KAT_128_128.txt.128 LWC_AEAD_KAT_128_128.txt
python3 -m pytest -k aead_128_kat --cache-clear -v

# clean up
rm LWC_*_KAT_*.txt

popd

# ---
