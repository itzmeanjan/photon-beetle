#!/usr/bin/python3

"""
  Before using `photon_beetle` library module, make sure you've run
  `make lib` and generated shared library object, which is loaded
  here; then all function calls are forwarded to respective C++
  implementation, executed on host CPU.

  Author: Anjan Roy <hello@itzmeanjan.in>

  Project: https://github.com/itzmeanjan/photon-beetle
"""

from typing import Tuple
from ctypes import CDLL, c_size_t, c_char_p, c_bool, create_string_buffer
from posixpath import exists, abspath

SO_PATH: str = abspath("../libphoton-beetle.so")
assert exists(SO_PATH), "Use `make lib` to generate shared library object !"

SO_LIB: CDLL = CDLL(SO_PATH)


def photon_beetle_hash(msg: bytes) -> bytes:
    """
    Given a N ( >= 0 ) -bytes input message, this function computes 32 -bytes
    Photon-Beetle-Hash digest
    """
    digest = create_string_buffer(32)

    args = [c_char_p, c_size_t, c_char_p]
    SO_LIB.photon_beetle_hash.argtypes = args
    SO_LIB.photon_beetle_hash(msg, len(msg), digest)

    return digest.raw


def photon_beetle_32_encrypt(
    key: bytes, nonce: bytes, data: bytes, text: bytes
) -> Tuple[bytes, bytes]:
    """
    Encrypts M ( >=0 ) -many plain text bytes, consuming 16 -bytes secret key,
    16 -bytes public message nonce & N ( >=0 ) -bytes associated data, while producing
    M -bytes cipher text & 16 -bytes authentication tag ( in order )
    """
    assert len(key) == 16, "Photon-Beetle-AEAD[32] takes 16 -bytes secret key !"
    assert len(nonce) == 16, "Photon-Beetle-AEAD[32] takes 16 -bytes nonce !"

    enc = create_string_buffer(len(text))
    tag = create_string_buffer(16)

    args = [
        c_char_p,
        c_char_p,
        c_char_p,
        c_size_t,
        c_char_p,
        c_char_p,
        c_size_t,
        c_char_p,
    ]
    SO_LIB.photon_beetle_32_encrypt.argtypes = args
    SO_LIB.photon_beetle_32_encrypt(
        key, nonce, data, len(data), text, enc, len(text), tag
    )

    return enc.raw, tag.raw


def photon_beetle_32_decrypt(
    key: bytes, nonce: bytes, tag: bytes, data: bytes, enc: bytes
) -> Tuple[bool, bytes]:
    """
    Decrypts M ( >=0 ) -many cipher text bytes, consuming 16 -bytes secret key,
    16 -bytes public message nonce, 16 -bytes authentication tag & N ( >=0 ) -bytes
    associated data, while producing boolean flag denoting verification status ( which
    must hold truth value, check before consuming decrypted output bytes ) &
    M -bytes plain text ( in order )
    """
    assert len(key) == 16, "Photon-Beetle-AEAD[32] takes 16 -bytes secret key !"
    assert len(nonce) == 16, "Photon-Beetle-AEAD[32] takes 16 -bytes nonce !"
    assert len(tag) == 16, "Photon-Beetle-AEAD[32] takes 16 -bytes authentication tag !"

    dec = create_string_buffer(len(enc))

    args = [
        c_char_p,
        c_char_p,
        c_char_p,
        c_char_p,
        c_size_t,
        c_char_p,
        c_char_p,
        c_size_t,
    ]
    SO_LIB.photon_beetle_32_decrypt.argtypes = args
    SO_LIB.photon_beetle_32_decrypt.restype = c_bool

    f = SO_LIB.photon_beetle_32_decrypt(
        key, nonce, tag, data, len(data), enc, dec, len(enc)
    )

    return f, dec.raw


def photon_beetle_128_encrypt(
    key: bytes, nonce: bytes, data: bytes, text: bytes
) -> Tuple[bytes, bytes]:
    """
    Encrypts M ( >=0 ) -many plain text bytes, consuming 16 -bytes secret key,
    16 -bytes public message nonce & N ( >=0 ) -bytes associated data, while producing
    M -bytes cipher text & 16 -bytes authentication tag ( in order )
    """
    assert len(key) == 16, "Photon-Beetle-AEAD[128] takes 16 -bytes secret key !"
    assert len(nonce) == 16, "Photon-Beetle-AEAD[128] takes 16 -bytes nonce !"

    enc = create_string_buffer(len(text))
    tag = create_string_buffer(16)

    args = [
        c_char_p,
        c_char_p,
        c_char_p,
        c_size_t,
        c_char_p,
        c_char_p,
        c_size_t,
        c_char_p,
    ]
    SO_LIB.photon_beetle_128_encrypt.argtypes = args
    SO_LIB.photon_beetle_128_encrypt(
        key, nonce, data, len(data), text, enc, len(text), tag
    )

    return enc.raw, tag.raw


def photon_beetle_128_decrypt(
    key: bytes, nonce: bytes, tag: bytes, data: bytes, enc: bytes
) -> Tuple[bool, bytes]:
    """
    Decrypts M ( >=0 ) -many cipher text bytes, consuming 16 -bytes secret key,
    16 -bytes public message nonce, 16 -bytes authentication tag & N ( >=0 ) -bytes
    associated data, while producing boolean flag denoting verification status ( which
    must hold truth value, check before consuming decrypted output bytes ) &
    M -bytes plain text ( in order )
    """
    assert len(key) == 16, "Photon-Beetle-AEAD[128] takes 16 -bytes secret key !"
    assert len(nonce) == 16, "Photon-Beetle-AEAD[128] takes 16 -bytes nonce !"
    assert (
        len(tag) == 16
    ), "Photon-Beetle-AEAD[128] takes 16 -bytes authentication tag !"

    dec = create_string_buffer(len(enc))

    args = [
        c_char_p,
        c_char_p,
        c_char_p,
        c_char_p,
        c_size_t,
        c_char_p,
        c_char_p,
        c_size_t,
    ]
    SO_LIB.photon_beetle_128_decrypt.argtypes = args
    SO_LIB.photon_beetle_128_decrypt.restype = c_bool

    f = SO_LIB.photon_beetle_128_decrypt(
        key, nonce, tag, data, len(data), enc, dec, len(enc)
    )

    return f, dec.raw


if __name__ == "__main__":
    print("Use `photon_beetle` as library module !")
