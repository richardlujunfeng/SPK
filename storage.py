# -*- coding: utf-8 -*-
from __future__ import print_function
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

        tmp = []
        for j in result_point.data:
            if isinstance(j, paillier.EncryptedNumber):
                tmp.append(private_key.decrypt(j))

        result_set_plaintext.append(tmp)
    
    for i in range(k):
        if not result_set_origin:
            break
        result_set_orgin_point = result_set_origin.popleft()
        result_set.append(result_set_orgin_point)







def pack_and_encrypt(value1, value2):  
    packed_value = (value1 << 32) | value2   
    public_key = get_public_key()  

    encrypted_packed_value = public_key.encrypt(packed_value)  
    return encrypted_packed_value  

def decrypt_and_unpack(encrypted_packed_value):  
    private_key = get_private_key()
    packed_value = private_key.decrypt(encrypted_packed_value)  
  
    value1 = packed_value >> 32
    value2 = packed_value & 0xFFFFFFFF
    return value1, value2  


