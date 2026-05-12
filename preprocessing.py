from __future__ import print_function
from storage import *
from queryprocessing import *
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
from concurrent.futures import ProcessPoolExecutor
from functools import wraps
from itertools import islice
from phe import EncodedNumber, paillier
from phe.util import invert, powmod, getprimeover, isqrt
import numpy as np
from phe import PaillierPublicKey, PaillierPrivateKey, EncryptedNumber
import copy
_MAX_LENGTH = 80
_paillier_worker_pk = None
_pairing_worker_pk = None


def _paillier_encrypt_worker_init(public_key):
    global _paillier_worker_pk
    _paillier_worker_pk = public_key


def _paillier_encrypt_worker_one(x):
    return _paillier_worker_pk.encrypt(x)


def _parallel_paillier_encrypt(values, public_key, max_workers):
    if not values:
        return []
    chunksize = max(1, len(values) // (max_workers * 8))
    with ProcessPoolExecutor(max_workers=max_workers, initializer=_paillier_encrypt_worker_init, initargs=(public_key,)) as pool:
        return list(pool.map(_paillier_encrypt_worker_one, values, chunksize=chunksize))


def _pairing_encrypt_worker_init(pk):
    global _pairing_worker_pk
    _pairing_worker_pk = pk


def _pairing_encrypt_worker_one(val):
    from pairing_proxy_access import encrypt_coordinate

    return encrypt_coordinate(_pairing_worker_pk, val)


def _parallel_pairing_encrypt(values, pk, max_workers):
    if not values:
        return []
    chunksize = max(1, len(values) // (max_workers * 8))
    with ProcessPoolExecutor(max_workers=max_workers, initializer=_pairing_encrypt_worker_init, initargs=(pk,)) as pool:
        return list(pool.map(_pairing_encrypt_worker_one, values, chunksize=chunksize))

class Node(object):

    def __init__(self, data=None, left=None, right=None, distance=None):
        self.data = data
        self.left = left
        self.right = right
        self.distance = None

    def __hash__(self):
        return hash((self.value, hash(self.left), hash(self.right)))

    @property
    def is_leaf(self):
        return not self.data or all((not bool(c) for c, p in self.children))

    def preorder(self):
        if not self:
            return
        yield self
        if self.left:
            for x in self.left.preorder():
                yield x
        if self.right:
            for x in self.right.preorder():
                yield x

    def inorder(self):
        if not self:
            return
        if self.left:
            for x in self.left.inorder():
                yield x
        yield self
        if self.right:
            for x in self.right.inorder():
                yield x

    def postorder(self):
        if not self:
            return
        if self.left:
            for x in self.left.postorder():
                yield x
        if self.right:
            for x in self.right.postorder():
                yield x
        yield self

    @property
    def children(self):
        if self.left and self.left.data is not None:
            yield (self.left, 0)
        if self.right and self.right.data is not None:
            yield (self.right, 1)

    def set_child(self, index, child):
        if index == 0:
            self.left = child
        else:
            self.right = child

    def height(self):
        min_height = int(bool(self))
        return max([min_height] + [c.height() + 1 for c, p in self.children])

    def get_child_pos(self, child):
        for c, pos in self.children:
            if child == c:
                return pos

    def __repr__(self):
        return '<%(cls)s - %(data)s>' % dict(cls=self.__class__.__name__, data=repr(self.data))

    def __nonzero__(self):
        return self.data is not None
    __bool__ = __nonzero__

    def __eq__(self, other):
        if isinstance(other, tuple):
            return self.data == other
        else:
            return self.data == other.data

    def __hash__(self):
        return id(self)

def require_axis(f):

    @wraps(f)
    def _wrapper(self, *args, **kwargs):
        if None in (self.axis, self.sel_axis):
            raise ValueError('%(func_name) requires the node %(node)s to have an axis and a sel_axis function' % dict(func_name=f.__name__, node=repr(self)))
        return f(self, *args, **kwargs)
    return _wrapper

class KDNode(Node):

    def __init__(self, data=None, left=None, right=None, axis=0, sel_axis=None, dimensions=0, HashValue_raw=None, height=None):
        super(KDNode, self).__init__(data, left, right)
        self.axis = axis
        self.sel_axis = sel_axis
        self.dimensions = dimensions
        self.height = 0
        self.HashValue_raw = HashValue_raw

    @require_axis
    def add(self, point):
        current = self
        while True:
            check_dimensionality([point], dimensions=current.dimensions)
            if current.data is None:
                current.data = point
                return current
            if point[current.axis] < current.data[current.axis]:
                if current.left is None:
                    current.left = current.create_subnode(point)
                    return current.left
                else:
                    current = current.left
            elif current.right is None:
                current.right = current.create_subnode(point)
                return current.right
            else:
                current = current.right

    @require_axis
    def create_subnode(self, data):
        return self.__class__(data, axis=self.sel_axis(self.axis), sel_axis=self.sel_axis, dimensions=self.dimensions)

    @require_axis
    def find_replacement(self):
        if self.right:
            child, parent = self.right.extreme_child(min, self.axis)
        else:
            child, parent = self.left.extreme_child(max, self.axis)
        return (child, parent if parent is not None else self)

    def should_remove(self, point, node):
        if not self.data == point:
            return False
        return node is None or node is self

    @require_axis
    def remove(self, point, node=None):
        if not self:
            return
        if self.should_remove(point, node):
            return self._remove(point)
        if self.left and self.left.should_remove(point, node):
            self.left = self.left._remove(point)
        elif self.right and self.right.should_remove(point, node):
            self.right = self.right._remove(point)
        if point[self.axis] <= self.data[self.axis]:
            if self.left:
                self.left = self.left.remove(point, node)
        if point[self.axis] >= self.data[self.axis]:
            if self.right:
                self.right = self.right.remove(point, node)
        return self

    @require_axis
    def _remove(self, point):
        if self.is_leaf:
            self.data = None
            return self
        root, max_p = self.find_replacement()
        tmp_l, tmp_r = (self.left, self.right)
        self.left, self.right = (root.left, root.right)
        root.left, root.right = (tmp_l if tmp_l is not root else self, tmp_r if tmp_r is not root else self)
        self.axis, root.axis = (root.axis, self.axis)
        if max_p is not self:
            pos = max_p.get_child_pos(root)
            max_p.set_child(pos, self)
            max_p.remove(point, self)
        else:
            root.remove(point, self)
        return root

    @property
    def is_balanced(self):
        left_height = self.left.height() if self.left else 0
        right_height = self.right.height() if self.right else 0
        if abs(left_height - right_height) > 1:
            return False
        return all((c.is_balanced for c, _ in self.children))

    def rebalance(self):
        return create([x.data for x in self.inorder()])

    def axis_dist(self, point, axis):
        return math.pow(self.data[axis] - point[axis], 2)

    def dist(self, point):
        r = range(self.dimensions)
        return sum([self.axis_dist(point, i) for i in r])

    def search_knn(self, point, k, dist=None):
        if k < 1:
            raise ValueError('k must be greater than 0.')
        if dist is None:
            get_dist = lambda n: n.dist(point)
        else:
            get_dist = lambda n: dist(n.data, point)
        results = []
        self._search_node(point, k, results, get_dist, itertools.count())
        return [(node, -d) for d, _, node in sorted(results, reverse=True)]

    def _search_node(self, point, k, results, get_dist, counter):
        if not self:
            return
        nodeDist = get_dist(self)
        item = (-nodeDist, next(counter), self)
        if len(results) >= k:
            if -nodeDist > results[0][0]:
                heapq.heapreplace(results, item)
        else:
            heapq.heappush(results, item)
        split_plane = self.data[self.axis]
        plane_dist = point[self.axis] - split_plane
        plane_dist2 = plane_dist * plane_dist
        if point[self.axis] < split_plane:
            if self.left is not None:
                self.left._search_node(point, k, results, get_dist, counter)
        elif self.right is not None:
            self.right._search_node(point, k, results, get_dist, counter)
        if -plane_dist2 > results[0][0] or len(results) < k:
            if point[self.axis] < self.data[self.axis]:
                if self.right is not None:
                    self.right._search_node(point, k, results, get_dist, counter)
            elif self.left is not None:
                self.left._search_node(point, k, results, get_dist, counter)

    @require_axis
    def search_nn(self, point, dist=None):
        return next(iter(self.search_knn(point, 1, dist)), None)

    def _search_nn_dist(self, point, dist, results, get_dist):
        if not self:
            return
        nodeDist = get_dist(self)
        if nodeDist < dist:
            results.append(self.data)
        split_plane = self.data[self.axis]
        if point[self.axis] <= split_plane + dist:
            if self.left is not None:
                self.left._search_nn_dist(point, dist, results, get_dist)
        if point[self.axis] >= split_plane - dist:
            if self.right is not None:
                self.right._search_nn_dist(point, dist, results, get_dist)

    @require_axis
    def search_nn_dist(self, point, distance, best=None):
        results = []
        get_dist = lambda n: n.dist(point)
        self._search_nn_dist(point, distance, results, get_dist)
        return results

    @require_axis
    def is_valid(self):
        if not self:
            return True
        if self.left and self.data[self.axis] < self.left.data[self.axis]:
            return False
        if self.right and self.data[self.axis] > self.right.data[self.axis]:
            return False
        return all((c.is_valid() for c, _ in self.children)) or self.is_leaf

    def extreme_child(self, sel_func, axis):
        max_key = lambda child_parent: child_parent[0].data[axis]
        me = [(self, None)] if self else []
        child_max = [c.extreme_child(sel_func, axis) for c, _ in self.children]
        child_max = [(c, p if p is not None else self) for c, p in child_max]
        candidates = me + child_max
        if not candidates:
            return (None, None)
        return sel_func(candidates, key=max_key)

def create(point_list, dimensions=0, axis=0):
    if not point_list:
        return None
    point_list.sort(key=lambda point: point[axis])
    median = len(point_list) // 2
    dimensions = check_dimensionality(point_list, dimensions)
    node = KDNode(point_list[median])
    node.left = create(point_list[:median], dimensions, (axis + 1) % dimensions)
    node.right = create(point_list[median + 1:], dimensions, (axis + 1) % dimensions)
    if node.left and node.right:
        node.height = max(node.left.height, node.right.height) + 1
    elif node.left:
        node.height = node.left.height + 1
    elif node.right:
        node.height = node.right.height + 1
    return node

def check_dimensionality(point_list, dimensions=None):
    dimensions = dimensions or len(point_list[0])
    for p in point_list:
        if len(p) != dimensions:
            raise ValueError('All Points in the point_list must have the same dimensionality')
    return dimensions

def level_order(tree, include_all=False):
    q = deque()
    q.append(tree)
    while q:
        node = q.popleft()
        yield node
        if include_all or node.left:
            q.append(node.left or node.__class__())
        if include_all or node.right:
            q.append(node.right or node.__class__())

def visualize(tree, max_level=100, node_width=10, left_padding=5):
    pass

def safe_repr(obj, short=False):
    try:
        result = repr(obj)
    except Exception:
        result = object.__repr__(obj)
    if not short or len(result) < _MAX_LENGTH:
        return result
    return result[:_MAX_LENGTH] + ' [truncated]...'

def test_create_function():
    tree = KDNode()
    point1 = [2, 3, 4]
    point2 = [4, 5, 6]
    point3 = [7, 8, 9]
    tree = create([point1, point2, point3])
    tree1 = create([(2, 2), (2, 1), (2, 3)])
    res, dist = tree.search_knn((1, 2, 3), 2)
    return tree

def random_tree(nodes=20, dimensions=3, minval=0, maxval=100):
    points = list(islice(random_points(), 0, nodes))
    tree = create(points)
    return tree

def random_point(dimensions=3, minval=0, maxval=100):
    return tuple((random.randint(minval, maxval) for _ in range(dimensions)))

def random_points(dimensions=3, minval=0, maxval=100):
    while True:
        yield random_point(dimensions, minval, maxval)

def main_process_function(tree):
    query_point = [2, 3, 5]
    knn_result = tree.search_knn(query_point, 2)

def test_remove_duplicates():
    points = [(1, 1)] * 100
    tree = create(points)
    random.shuffle(points)
    while points:
        point = points.pop(0)
        tree = tree.remove(point)
        remaining_points = len(points)
        nodes_in_tree = len(list(tree.inorder()))
    return tree

def test_remove(num=100):
    for i in range(num):
        do_random_remove()

def do_random_remove():
    points = list(set(islice(random_points(), 0, 3)))
    tree = create(points)
    visualize(tree)
    random.shuffle(points)
    point = points.pop(0)
    tree = tree.remove(point)
    visualize(tree)

def test_remove_empty_tree():
    tree = create(dimensions=2)
    tree.remove((1, 2))
user_public_key = None

def DO_outsource_to_server(tree, public_key):
    public_key = get_public_key()
    if tree is None:
        return
    q = deque()
    q.append(tree)
    positions = []
    plaintexts = []
    last_payload = None
    while q:
        node = q.popleft()
        for i, node_data in enumerate(node.data):
            positions.append((node, i))
            plaintexts.append(node_data)
        last_payload = node.data
        if node.left:
            q.append(node.left or node.__class__())
        if node.right:
            q.append(node.right or node.__class__())
    parallel = os.environ.get('SPK_OUTSOURCE_PARALLEL', '1').strip().lower() not in ('0', 'false', 'no')
    workers_cfg = int(os.environ.get('SPK_ENCRYPT_WORKERS', '0'))
    workers = workers_cfg if workers_cfg > 0 else min(os.cpu_count() or 4, 32)
    min_parallel = max(16, workers * 2)
    encrypted = plaintexts
    if plaintexts:
        if parallel and len(plaintexts) >= min_parallel and workers > 1:
            try:
                encrypted = _parallel_paillier_encrypt(plaintexts, public_key, workers)
            except Exception:
                encrypted = [public_key.encrypt(x) for x in plaintexts]
        else:
            encrypted = [public_key.encrypt(x) for x in plaintexts]
        for (node, i), c in zip(positions, encrypted):
            node.data[i] = c
    if last_payload is not None:
        with open('encrypted_object.pkl', 'wb') as file:
            pickle.dump(last_payload, file)
    return tree

def DO_outsource_coordinates_pairing(tree, key_hierarchy=None):
    from pairing_context import get_pairing_hierarchy
    from pairing_proxy_access import PairingStoredCoord, encrypt_coordinate
    kh = key_hierarchy if key_hierarchy is not None else get_pairing_hierarchy()
    pk = kh.public
    if tree is None:
        return tree
    stack = deque()
    stack.append(tree)
    last_payload = None
    positions = []
    plaintexts = []
    while stack:
        node = stack.popleft()
        for i, node_data in enumerate(node.data):
            val = int(round(node_data)) % pk.params.q
            positions.append((node, i))
            plaintexts.append(val)
        last_payload = node.data
        if node.left:
            stack.append(node.left or node.__class__())
        if node.right:
            stack.append(node.right or node.__class__())
    encrypted = plaintexts
    if plaintexts:
        parallel = os.environ.get('SPK_OUTSOURCE_PARALLEL', '1').strip().lower() not in ('0', 'false', 'no')
        workers_cfg = int(os.environ.get('SPK_ENCRYPT_WORKERS', '0'))
        workers = workers_cfg if workers_cfg > 0 else min(os.cpu_count() or 4, 32)
        min_parallel = max(16, workers * 2)
        if parallel and len(plaintexts) >= min_parallel and workers > 1:
            try:
                encrypted = _parallel_pairing_encrypt(plaintexts, pk, workers)
            except Exception:
                encrypted = [encrypt_coordinate(pk, v) for v in plaintexts]
        else:
            encrypted = [encrypt_coordinate(pk, v) for v in plaintexts]
        for (node, i), c in zip(positions, encrypted):
            node.data[i] = PairingStoredCoord(c)
    if last_payload is not None:
        with open('encrypted_object.pkl', 'wb') as file:
            pickle.dump(last_payload, file)
    return tree

def User_send_query_request(query_point, public_key):
    weight = 1
    from storage import pack_and_encrypt, pack_multipack_query_ciphertext
    coords = list(query_point)
    multipack = pack_multipack_query_ciphertext(coords, weight, public_key)
    if multipack is not None:
        query_point[:] = multipack
        return
    query_point[:] = coords
    for index, query_per_dimension_value in enumerate(query_point):
        query_point[index] = pack_and_encrypt(query_per_dimension_value, weight)
