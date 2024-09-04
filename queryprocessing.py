# -*- coding: utf-8 -*-
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



def traversal_VO_Tree(root):
    if not root:
        return 
    print("---------------------")
    print(private_key.decrypt(root.data[0]), private_key.decrypt(root.data[1]))

    print(root.data)
    print("********************")
    traversal_VO_Tree(root.left)
    traversal_VO_Tree(root.right)
    
    return 


def Cloud_Processing(query_point, tree, k, Root_Hash, tree_height):
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
    encrypt_perturbation_number = public_key.encrypt(perturbation_number)
    prune_flag = False
    com1 = 0
    com2 = 0
    com3 = 0
    COP = 0
    start_time = time.time()
    while q:
        node = q.popleft()

        now_axis = node.axis 

        node_duplicate = copy.deepcopy(node)
        node_duplicate.data[now_axis] = node_duplicate.data[now_axis] + perturbation_number

        query_point[now_axis] = query_point[now_axis] + perturbation_number

        if node_duplicate.left is None and node_duplicate.right is None:
            node_duplicate.data[now_axis] = node_duplicate.data[now_axis] + 0
        start_time1 = time.time()
        prune_distance = Secure_distance_compute(node_duplicate.data[now_axis], query_point[now_axis])
        end_time1 = time.time()
        com1 = end_time1 - start_time1 + com1

        query_point[now_axis] = query_point[now_axis] - perturbation_number
        node_duplicate.data[now_axis] = node_duplicate.data[now_axis] - perturbation_number


        if T == None:
            T = math.inf
        
        start_time4 = time.time()

        if T < prune_distance and T != None and prune_flag == False:
            node.distance = prune_distance
            non_result_queue_set.append(node)
            combined_digest = compute_hash_recursive(node)    

            node.HashValue_raw = combined_digest
            node.left = None
            node.right = None
            continue
        end_time4 = time.time()
        COP = end_time4 - start_time4 + COP



        if prune_flag == False:
            node.distance = 0
            for i, node_data in enumerate(node_duplicate.data):
                #secure compute the distance between node data and query point 
                node_data = node_data + perturbation_number
                query_point[i] = query_point[i] + perturbation_number
                #leaf node
                if node.height == tree_height - 1:
                    node_data = node_data + 0
                start_time2 = time.time()
                node.distance = node.distance + Secure_distance_compute(node_data, query_point[i])
                end_time2 = time.time()
                com2 = end_time2 - start_time2 + com2
                query_point[i] = query_point[i] - perturbation_number
        

        if node:
            #if Secure_integer_compare_protocol(T, node.distance) == 0:
            if node.distance < T or T == math.inf or len(result_queue_set) < k: 
                result_queue_set.append(node)
                #T = node.distance
                if len(result_queue_set) == 1:
                    T = node.distance 
                if len(result_queue_set) > 1 and len(result_queue_set) <= k:
                    if node.distance > T:
                        T = node.distance
                start_time3 = time.time()
                if len(result_queue_set) > k:
                #pop the max encryted position 
                    result_queue_set, non_result_queue_set, T = Secure_pop_maximum_protocol(result_queue_set, non_result_queue_set, node, T, k)
                end_time3 = time.time()
                com3 = end_time3 - start_time3 + com3
        #Prune the child nodes directly
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
    
    end_time = time.time()

    return result_queue_set, non_result_queue_set, T, VO_Tree_Root, Root_Hash, tree


def DFS_Tree_Root(node, combined_result):
    if node is None:
        return combined_result
    combined_result = DFS_Tree_Root(node.left, combined_result)
    combined_result = DFS_Tree_Root(node.right, combined_result)
    if node.data:

        if combined_result:
            if node.left is None and node.right is None:
                combined_result = node.data

                tree_root_hash  = hashlib.sha256(str(combined_result).encode())
                combined_result = tree_root_hash.hexdigest()
            else:

                combined_result = list(str(combined_result)) + node.data

                tree_root_hash  = hashlib.sha256(str(combined_result).encode())
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

            tree_root_hash  = hashlib.sha256(str(combined_result).encode())
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
    current_hash = hash_function((str(left_hash) + str(right_hash) + str(node_value)))
    return current_hash

def compare_hashes(precomputed_hashes, computed_hashes):
    for key, value in precomputed_hashes.items():
        if key in computed_hashes and computed_hashes[key] == value:
            print(f"节点{key}的哈希值匹配成功。")
        else:
            print(f"节点{key}的哈希值不匹配。")

def client_compute_root_hash(VO_Tree_Root):
    VO_root_hash = None
    combined_result = None
    print("**********")
    print("client verify the result process")
    combined_result = DFS_VO_Tree_Root_Hash(VO_Tree_Root, combined_result)
    hash_object = hashlib.sha256(str(combined_result).encode())
    hash_value = hash_object.hexdigest()
    return hash_value


def check_result_soundness_completeness(non_result_set, result_set_final, VO_Tree_Root, T, Processed_Root_HMAC):
    private_key =  private_key = get_private_key()
    computed_hashes = {}
    root_hash = compute_hash_recursive(VO_Tree_Root)

    if root_hash == Processed_Root_HMAC:
       print("The result is completed.")
    else:
        print("The result is not completed.")

        print("non_result_set is ")
    
    for i in range(len(non_result_set)):

        if isinstance(non_result_set[i].data[0], EncryptedNumber):
            for j,elment in enumerate(non_result_set[i].data):
                non_result_set[i].data[j] = private_key.decrypt(elment)
    
    #print(non_result_set)
    final_result_distance_compare = 1
    for non_result_element in non_result_set:
        final_result_distance_compare *=(non_result_element.distance - T)
        if final_result_distance_compare < 0:
            print("The result is tampered.")
            break
        else:
            final_result_distance_compare = 1
    if final_result_distance_compare > 0:
        print("The result is correct.")
        

def concatenation_tree_data(node, combined_result):
    print("---------------------")
    print("The client compute the tree data hash")
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
        size += sum(get_object_size(item) for item in obj)
    elif isinstance(obj, dict):
        size += sum(get_object_size(k) + get_object_size(v) for k, v in obj.items())
    return size

def get_tree_size(node):
    if node is None:
        return 0
    return get_object_size(node) + get_tree_size(node.left) + get_tree_size(node.right)

