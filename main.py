from storage import *
from queryprocessing import *
from preprocessing import *
from main import *
from keys import get_private_key, get_public_key
import threading
import os
import secrets
import hmac
import hashlib
import re
import heapq
import itertools
import operator
import math
import sys
import random
import logging
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

from spk_engine import load_cli_run_spec, run_spk_pipeline

_MAX_LENGTH = 80


def main(number_of_points, k, d):
    run_spk_pipeline(number_of_points, k, d, _g=sys.modules[__name__].__dict__)


if __name__ == '__main__':
    if os.environ.get('SPK_SHOW_BACKEND', '').strip().lower() in ('1', 'true', 'yes'):
        import phe.util as _phe_util

        try:
            import gmpy2 as _gmpy2_probe

            _gmpy2_ok = 'yes (%s)' % getattr(_gmpy2_probe, '__version__', '?')
        except ImportError as _e:
            _gmpy2_ok = 'no (%s)' % _e
        print('SPK backend: python-phe HAVE_GMP={} gmpy2={}'.format(_phe_util.HAVE_GMP, _gmpy2_ok))
    print('Execution started.')
    points_list, d, k = load_cli_run_spec()
    for points in points_list:
        main(points, k, d)
