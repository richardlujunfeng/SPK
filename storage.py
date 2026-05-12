from __future__ import print_function
import gmp_bootstrap
from queryprocessing import *
from preprocessing import *
from main import *
import os
import secrets
import hmac
import hashlib
import re
import collections
import heapq
import itertools
import operator
import math
import sys
import random
import logging
import time
import unittest
import doctest
import collections
import utils
import base64
import pickle
import queue
from base64 import b64encode, b64decode
from collections import deque
from functools import wraps
from itertools import islice
from phe import EncodedNumber, paillier
from phe.util import invert, powmod, getprimeover, isqrt
import numpy as np
from phe import PaillierPublicKey, PaillierPrivateKey, EncryptedNumber
import copy
_MAX_LENGTH = 80
_QUERY_HALF_BITS = 32

def query_multi_pack_enabled():
    return os.environ.get('SPK_QUERY_MULTI_PACK', '1').strip().lower() not in ('0', 'false', 'no')


def query_pack_slot_config():
    slots = int(os.environ.get('SPK_QUERY_PACK_SLOTS', '100'))
    bits = int(os.environ.get('SPK_QUERY_PACK_SLOT_BITS', '10'))
    return (max(4, slots), max(1, bits))


def multipack_query_fits(public_key, slot_count, slot_bits, dimension_count):
    if slot_count * slot_bits >= public_key.n.bit_length() - 48:
        return False
    if 1 + 2 * dimension_count > slot_count:
        return False
    return True


def pack_slots_to_plaintext(flat_values, slot_bits, slot_count):
    mask = (1 << slot_bits) - 1
    packed = 0
    for i in range(slot_count):
        v = int(flat_values[i]) & mask
        packed |= v << i * slot_bits
    return packed


def unpack_slots_from_plaintext(packed_plain, slot_bits, slot_count):
    mask = (1 << slot_bits) - 1
    return [packed_plain >> i * slot_bits & mask for i in range(slot_count)]


def pack_multipack_query_ciphertext(coords_plain, weight, public_key):
    if not query_multi_pack_enabled():
        return None
    slot_count, slot_bits = query_pack_slot_config()
    d = len(coords_plain)
    if not multipack_query_fits(public_key, slot_count, slot_bits, d):
        return None
    flat = [d]
    for q in coords_plain:
        flat.append(int(round(q)))
        flat.append(int(weight))
    while len(flat) < slot_count:
        flat.append(0)
    mask = (1 << slot_bits) - 1
    for v in flat:
        if int(v) & ~mask:
            return None
    pt = pack_slots_to_plaintext(flat, slot_bits, slot_count)
    return [public_key.encrypt(pt)]


def build_qp_packed_plain_list(query_point, private_key):
    slot_count, slot_bits = query_pack_slot_config()
    if query_multi_pack_enabled() and len(query_point) == 1:
        mega_plain = int(private_key.decrypt(query_point[0]))
        slots = unpack_slots_from_plaintext(mega_plain, slot_bits, slot_count)
        d = slots[0]
        if d < 1 or 1 + 2 * d > slot_count:
            raise ValueError('invalid multipack query ciphertext')
        qp_packed_plain = []
        for i in range(d):
            coord = slots[1 + 2 * i]
            weight = slots[1 + 2 * i + 1]
            qp_packed_plain.append(coord << _QUERY_HALF_BITS | weight)
        return qp_packed_plain
    return [int(private_key.decrypt(query_point[i])) for i in range(len(query_point))]


def query_uses_single_multipack_cipher(query_point):
    return query_multi_pack_enabled() and len(query_point) == 1

def print_plaintext_of_result(result_set, k):
    public_key = get_public_key()
    private_key = get_private_key()
    result_set_plaintext = []
    result_set_origin = deque()
    for i in range(k):
        if not result_set:
            break
        result_point = result_set.popleft()
        result_set_origin.append(result_point)
        from pairing_proxy_access import PairingStoredCoord, decrypt_coordinate
        from pairing_context import get_pairing_hierarchy
        tmp = []
        for j in result_point.data:
            if isinstance(j, paillier.EncryptedNumber):
                tmp.append(private_key.decrypt(j))
            elif isinstance(j, PairingStoredCoord):
                kh = get_pairing_hierarchy()
                tmp.append(decrypt_coordinate(j.ct, kh))
        result_set_plaintext.append(tmp)
    for i in range(k):
        if not result_set_origin:
            break
        result_set_orgin_point = result_set_origin.popleft()
        result_set.append(result_set_orgin_point)

def pack_and_encrypt(value1, value2):
    packed_value = value1 << 32 | value2
    public_key = get_public_key()
    encrypted_packed_value = public_key.encrypt(packed_value)
    return encrypted_packed_value

def decrypt_and_unpack(encrypted_packed_value):
    private_key = get_private_key()
    packed_value = private_key.decrypt(encrypted_packed_value)
    packed_value = int(packed_value)
    value1 = packed_value >> 32
    value2 = packed_value & 4294967295
    return (value1, value2)
