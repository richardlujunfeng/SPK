from __future__ import print_function
from storage import *
from shared import *
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
from pairing_proxy_access import PairingStoredCoord
_MAX_LENGTH = 80

def _shallow_node_duplicate(node):
    dup = copy.copy(node)
    dup.data = list(node.data)
    return dup

def traversal_VO_Tree(root):
    if not root:
        return
    traversal_VO_Tree(root.left)
    traversal_VO_Tree(root.right)
    return

def Cloud_Processing(query_point, tree, k, Root_Hash, tree_height):
    from storage import build_qp_packed_plain_list, query_uses_single_multipack_cipher
    if tree is None:
        return
    if tree is None:
        return
    result_queue_set = deque()
    non_result_queue_set = deque()
    VO_Tree_Root = tree
    q = deque()
    q.append(tree)
    T = None
    perturbation_number = 1
    public_key = get_public_key()
    prune_flag = False
    private_key = get_private_key()
    mega_qp = query_uses_single_multipack_cipher(query_point)
    qp_packed_plain = build_qp_packed_plain_list(query_point, private_key)
    _precompute_vo_subtree_hashes(tree)
    while q:
        node = q.popleft()
        now_axis = node.axis
        node_duplicate = _shallow_node_duplicate(node)
        perturb_plain = perturbation_number
        coord_at_axis = node_duplicate.data[now_axis]
        q_cipher = query_point[0] if mega_qp else query_point[now_axis]
        plain_prune_axis_paillier = None
        if isinstance(coord_at_axis, PairingStoredCoord):
            if not mega_qp:
                query_point[now_axis] = query_point[now_axis] + perturbation_number
            if node_duplicate.left is None and node_duplicate.right is None:
                pass
            prune_distance = Secure_distance_compute(coord_at_axis, q_cipher, perturb_plain_offset=perturb_plain, query_pv_plain=qp_packed_plain[now_axis], query_pv_shift=perturbation_number)
            if not mega_qp:
                query_point[now_axis] = query_point[now_axis] - perturbation_number
        else:
            if not mega_qp:
                query_point[now_axis] = query_point[now_axis] + perturbation_number
            plain_prune_axis_paillier = int(private_key.decrypt(coord_at_axis))
            cp = plain_prune_axis_paillier + perturbation_number
            prune_distance = secure_paillier_distance_sq_encrypted(cp, qp_packed_plain[now_axis], perturbation_number)
            if not mega_qp:
                query_point[now_axis] = query_point[now_axis] - perturbation_number
        if T == None:
            T = 1e+20
            T = public_key.encrypt(T)
        if Secure_integer_compare_protocol(T, prune_distance) == 0 and T != None and (prune_flag == False):
            node.distance = prune_distance
            non_result_queue_set.append(node)
            combined_digest = node._vo_subtree_hash
            node.HashValue_raw = combined_digest
            node.left = None
            node.right = None
            continue
        if prune_flag == False:
            node.distance = 0
            perturb_plain = perturbation_number
            for i, node_data in enumerate(node_duplicate.data):
                q_cipher = query_point[0] if mega_qp else query_point[i]
                if isinstance(node_data, PairingStoredCoord):
                    if not mega_qp:
                        query_point[i] = query_point[i] + perturbation_number
                    if node.height == tree_height - 1:
                        pass
                    node.distance = node.distance + Secure_distance_compute(node_data, q_cipher, perturb_plain_offset=perturb_plain, query_pv_plain=qp_packed_plain[i], query_pv_shift=perturbation_number)
                    if not mega_qp:
                        query_point[i] = query_point[i] - perturbation_number
                else:
                    if not mega_qp:
                        query_point[i] = query_point[i] + perturbation_number
                    if plain_prune_axis_paillier is not None and i == now_axis:
                        plain_i = plain_prune_axis_paillier
                    else:
                        plain_i = int(private_key.decrypt(node_data))
                    cp_i = plain_i + perturbation_number
                    node.distance = node.distance + secure_paillier_distance_sq_encrypted(cp_i, qp_packed_plain[i], perturbation_number)
                    if not mega_qp:
                        query_point[i] = query_point[i] - perturbation_number
        if node:
            if Secure_distance_compute(node.distance, T) == 0 or T == math.inf or len(result_queue_set) < k:
                result_queue_set.append(node)
                if len(result_queue_set) == 1:
                    T = node.distance
                if len(result_queue_set) > 1 and len(result_queue_set) <= k:
                    if Secure_distance_compute(node.distance, T) == 0:
                        T = node.distance
                if len(result_queue_set) > k:
                    result_queue_set, non_result_queue_set, T = Secure_pop_maximum_protocol(result_queue_set, non_result_queue_set, node, T, k)
        if prune_flag == False:
            q_temp = deque()
            if node.left:
                q_temp.append(node.left or node.__class__())
            if node.right:
                q_temp.append(node.right or node.__class__())
            if node.height == tree_height - 1:
                random.shuffle(q_temp)
            while q_temp:
                q.append(q_temp.pop())
        prune_flag = False
    return (result_queue_set, non_result_queue_set, T, VO_Tree_Root, Root_Hash, tree)

def DFS_Tree_Root(node, combined_result):
    if node is None:
        return combined_result
    combined_result = DFS_Tree_Root(node.left, combined_result)
    combined_result = DFS_Tree_Root(node.right, combined_result)
    if node.data:
        if combined_result:
            if node.left is None and node.right is None:
                combined_result = node.data
                tree_root_hash = hashlib.sha256(str(combined_result).encode())
                combined_result = tree_root_hash.hexdigest()
            else:
                combined_result = list(str(combined_result)) + node.data
                tree_root_hash = hashlib.sha256(str(combined_result).encode())
                combined_result = tree_root_hash.hexdigest()
        else:
            combined_result = node.data
    return combined_result

def hash_function(value):
    return hash(str(value))

def DFS_VO_Tree_Root_Hash(node, combined_result):
    if node is None:
        return combined_result
    combined_result = DFS_VO_Tree_Root_Hash(node.left, combined_result)
    combined_result = DFS_VO_Tree_Root_Hash(node.right, combined_result)
    if node:
        if combined_result:
            if node.HashValue_raw:
                combined_result = list(combined_result) + list(node.HashValue_raw)
            else:
                combined_result = list(combined_result) + node.data
            tree_root_hash = hashlib.sha256(str(combined_result).encode())
            combined_result = tree_root_hash.hexdigest()
        else:
            combined_result = node.data
    return combined_result

def compute_hash_recursive(node):
    if node is None:
        return hash_function(None)
    node_value = tuple(node.data) if node.HashValue_raw else None
    if node.HashValue_raw:
        return node.HashValue_raw
    left_hash = compute_hash_recursive(node.left)
    right_hash = compute_hash_recursive(node.right)
    current_hash = hash_function(str(left_hash) + str(right_hash) + str(node_value))
    return current_hash

_HASH_NONE_NODE = None


def _cached_hash_none():
    global _HASH_NONE_NODE
    if _HASH_NONE_NODE is None:
        _HASH_NONE_NODE = hash_function(None)
    return _HASH_NONE_NODE


def _precompute_vo_subtree_hashes(root):
    order = []

    def postorder(n):
        if n is None:
            return
        postorder(n.left)
        postorder(n.right)
        order.append(n)

    postorder(root)
    for node in order:
        if getattr(node, 'HashValue_raw', None):
            node._vo_subtree_hash = node.HashValue_raw
        else:
            lh = node.left._vo_subtree_hash if node.left is not None else _cached_hash_none()
            rh = node.right._vo_subtree_hash if node.right is not None else _cached_hash_none()
            node_value = tuple(node.data) if node.HashValue_raw else None
            node._vo_subtree_hash = hash_function(str(lh) + str(rh) + str(node_value))


def compare_hashes(precomputed_hashes, computed_hashes):
    pass

def client_compute_root_hash(VO_Tree_Root):
    VO_root_hash = None
    combined_result = None
    combined_result = DFS_VO_Tree_Root_Hash(VO_Tree_Root, combined_result)
    hash_object = hashlib.sha256(str(combined_result).encode())
    hash_value = hash_object.hexdigest()
    return hash_value

def check_result_soundness_completeness(non_result_set, result_set_final, VO_Tree_Root, T, Processed_Root_HMAC):
    private_key = private_key = get_private_key()
    computed_hashes = {}
    root_hash = compute_hash_recursive(VO_Tree_Root)
    if root_hash == Processed_Root_HMAC:
        print('The result is completed.')
    for i in range(len(non_result_set)):
        if isinstance(non_result_set[i].data[0], EncryptedNumber):
            for j, elment in enumerate(non_result_set[i].data):
                non_result_set[i].data[j] = private_key.decrypt(elment)
    final_result_distance_compare = 1
    for non_result_element in non_result_set:
        final_result_distance_compare *= non_result_element.distance - T
        if final_result_distance_compare < 0:
            break
        else:
            final_result_distance_compare = 1
    if final_result_distance_compare > 0:
        print('The result is correct.')

def concatenation_tree_data(node, combined_result):
    combined_result = DFS_Tree_Root(node, combined_result)
    return combined_result

def copy_tree(root):
    if root is None:
        return None
    new_tree = Node(root.data)
    new_tree.left = copy_tree(root.left)
    new_tree.right = copy_tree(root.right)
    return new_tree

def height_of_binary_tree(node):
    if node is None:
        return 0
    else:
        left_height = height_of_binary_tree(node.left)
        right_height = height_of_binary_tree(node.right)
        return max(left_height, right_height) + 1

def calculate_total_tree_size(node):
    if node is None:
        return 0
    node_size = sys.getsizeof(node)
    left_size = calculate_total_tree_size(node.left)
    right_size = calculate_total_tree_size(node.right)
    return node_size + left_size + right_size

def get_object_size(obj):
    if obj is None:
        return 0
    size = sys.getsizeof(obj)
    if hasattr(obj, '__dict__'):
        for key, value in obj.__dict__.items():
            size += get_object_size(key) + get_object_size(value)
    elif isinstance(obj, (list, tuple, set, frozenset)):
        size += sum((get_object_size(item) for item in obj))
    elif isinstance(obj, dict):
        size += sum((get_object_size(k) + get_object_size(v) for k, v in obj.items()))
    return size

def get_tree_size(node):
    if node is None:
        return 0
    return get_object_size(node) + get_tree_size(node.left) + get_tree_size(node.right)
