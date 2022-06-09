#!/bin/bash

# Script for ease of execution of Known Answer Tests against Photon-Beetle implementation

# generate shared library object
make lib

# ---

mkdir -p tmp
pushd tmp

# download compressed NIST LWC submission of Sparkle
wget -O photon-beetle.zip https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-submissions/photon-beetle.zip
# uncomress
unzip photon-beetle.zip

# copy Known Answer Tests outside of uncompressed NIST LWC submission directory
cp photon-beetle/Implementations/crypto_hash/photonbeetlehash256rate32v1/LWC_HASH_KAT_256.txt ../

popd

# ---

# remove NIST LWC submission zip
rm -rf tmp

# move Known Answer Tests to execution directory
mv LWC_HASH_KAT_256.txt wrapper/python/

# ---

pushd wrapper/python

# run tests
python3 -m pytest -v

# clean up
rm LWC_*_KAT_*.txt

popd

# ---
