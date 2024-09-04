# -*- coding: utf-8 -*-
from storage import *
from queryprocessing import *
from preprocessing import *
from main import *
from keys import get_private_key, get_public_key  

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
# main.py  
from keys import get_private_key, get_public_key  


from phe import EncodedNumber, paillier
from phe.util import invert, powmod, getprimeover, isqrt
import numpy as np
from phe import PaillierPublicKey, PaillierPrivateKey, EncryptedNumber
import copy

_MAX_LENGTH = 80

# public_key, private_key = paillier.generate_paillier_keypair(n_length = 1024)


def main(number_of_points, k, d):
    private_key = get_private_key()  
    public_key = get_public_key()  
    print(f"正在处理 {number_of_points} 个数据点的数据集..., 查找top-k的前{k}个点")

    data = []

    filepath = YOUR_FILE_PATH
    with open(filepath, 'r') as f:    
        for line in f:
            line = re.split(r'\s+', line.strip())
            sample = line[:2]
            # sample = line[:number_of_points]
            T_sample = []
            for x in sample:
                if x == 'NaN' or int(float(x)) < 0:
                    T_sample.append(0)
                else:
                    T_sample.append(int(float(x)))
            data.append(T_sample)
            if len(data)>=number_of_points:
                break
    tree = create(data)

    tree_height = height_of_binary_tree(tree)   

    total_size = get_tree_size(tree) / (1024*1024)

    z = len(data[0])
    query_point = [0]*z

    start_time = time.time()
    query_result = tree.search_knn(query_point, 3)
    end_time = time.time()

    public_key = get_public_key()  
    start_time = time.time()
    tree = DO_outsource_to_server(tree, public_key)

    total_size = get_tree_size(tree) / (1024*1024)

    end_time = time.time()

    tree_combined_result = []
    tree_combined_op = tree

    start_time = time.time()

    Processed_Root_Hash = compute_hash_recursive(tree)
    end_time = time.time()

    User_send_query_request(query_point, public_key)

    result_set_final, non_result_set, T, VO_Tree_Root, Processed_Root_Hash, tree = Cloud_Processing(query_point, tree, k, Processed_Root_Hash, tree_height)

    voSize = get_tree_size(tree) / (1024*1024)

    start_time = time.time()
    
    check_result_soundness_completeness(non_result_set, result_set_final, VO_Tree_Root, T, Processed_Root_Hash)
    end_time = time.time()
    verify = end_time - start_time


if __name__ == "__main__":
    
    # points_list = [1000, 2000, 3000, 4000, 5000, 6000, 7000, 8000, 9000, 10000]
    points_list = [2000, 4000, 6000, 8000, 10000]

    # public_key, private_key = paillier.generate_paillier_keypair(n_length = 1024)

    d = 2
    k = 1
    for points in points_list:
        main(points, k, d)
