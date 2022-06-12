#!/usr/bin/python3

'''
  Before using `photon_beetle` library module, make sure you've run
  `make lib` and generated shared library object, which is loaded
  here; then all function calls are forwarded to respective C++
  implementation, executed on host CPU.

  Author: Anjan Roy <hello@itzmeanjan.in>

  Project: https://github.com/itzmeanjan/photon-beetle
'''

import ctypes as ct
import numpy as np
from posixpath import exists, abspath

SO_PATH: str = abspath('../libphoton-beetle.so')
assert exists(SO_PATH), 'Use `make lib` to generate shared library object !'

SO_LIB: ct.CDLL = ct.CDLL(SO_PATH)

u8 = np.uint8
len_t = ct.c_size_t
uint8_tp = np.ctypeslib.ndpointer(dtype=u8, ndim=1, flags='CONTIGUOUS')


def photon_beetle_hash(msg: bytes) -> bytes:
    '''
    Given a N ( >= 0 ) -bytes input message, this function computes 32 -bytes
    Photon-Beetle-Hash digest
    '''
    m_len = len(msg)
    msg_ = np.frombuffer(msg, dtype=u8)
    digest = np.empty(32, dtype=u8)

    args = [uint8_tp, len_t, uint8_tp]
    SO_LIB.photon_beetle_hash.argtypes = args

    SO_LIB.photon_beetle_hash(msg_, m_len, digest)

    digest_ = digest.tobytes()
    return digest_


if __name__ == '__main__':
    print('Use `photon_beetle` as library module !')
