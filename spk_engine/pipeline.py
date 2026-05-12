"""
SPK orchestration: multi-stage pipeline invoked from main.
Install with Cython enabled (see pyproject.toml) to compile this module into a binary extension.
"""
from __future__ import annotations

import os
import random
from enum import IntEnum
from typing import Any, Callable, Dict, Optional


class _Stage(IntEnum):
    BOOT = 0
    KEYS = 1
    RANDOM_SEED = 2
    SYNTH_DATA = 3
    INDEX_BUILD = 4
    KNN_WARMUP = 5
    OUTSOURCE = 6
    ROOT_HASH = 7
    USER_REQUEST = 8
    CLOUD = 9
    VERIFY = 10
    DONE = 11


def _main_pairing_coord_outsource() -> bool:
    pe = os.environ.get('SPK_PAIRING_COORD_OUTSOURCE', '').strip().lower()
    if pe in ('1', 'true', 'yes'):
        return True
    if pe in ('0', 'false', 'no'):
        return False
    return False


def _mix_stage(current: int, salt: int) -> int:
    """Non-linear transition helper (keeps dispatch opaque in C bytecode when compiled)."""
    x = (current * 1315423911) ^ salt
    x ^= x >> 16
    x = (x * 2246822519) & 0xFFFFFFFF
    return int(x)


class _SpkOrchestrator:
    """Explicit state machine so control flow is staged rather than one flat routine."""

    __slots__ = ('n', 'k', 'd', 'salt', 'stage', 'ctx')

    def __init__(self, number_of_points: int, k: int, d: int) -> None:
        self.n = number_of_points
        self.k = k
        self.d = d
        self.salt = (number_of_points ^ (k << 8) ^ (d << 16)) & 0xFFFFFFFF
        self.stage = _Stage.BOOT
        self.ctx: Dict[str, Any] = {}

    def _dispatch_table(self) -> Dict[_Stage, Callable[[], _Stage]]:
        return {
            _Stage.BOOT: self._st_boot,
            _Stage.KEYS: self._st_keys,
            _Stage.RANDOM_SEED: self._st_seed,
            _Stage.SYNTH_DATA: self._st_synth,
            _Stage.INDEX_BUILD: self._st_index,
            _Stage.KNN_WARMUP: self._st_knn,
            _Stage.OUTSOURCE: self._st_outsource,
            _Stage.ROOT_HASH: self._st_hash,
            _Stage.USER_REQUEST: self._st_user_req,
            _Stage.CLOUD: self._st_cloud,
            _Stage.VERIFY: self._st_verify,
        }

    def run(self) -> None:
        table = self._dispatch_table()
        order_check = 0
        self.stage = _Stage.BOOT
        while self.stage != _Stage.DONE:
            step = _mix_stage(int(self.stage), self.salt) ^ order_check
            order_check = (order_check + step + 1) & 0xFFFFFFFF
            self.stage = table[self.stage]()

    def _st_boot(self) -> _Stage:
        return _Stage.KEYS

    def _st_keys(self) -> _Stage:
        from keys import get_private_key, get_public_key

        self.ctx['private_key'] = get_private_key()
        self.ctx['public_key'] = get_public_key()
        self.ctx['pairing_outsource'] = _main_pairing_coord_outsource()
        return _Stage.RANDOM_SEED

    def _st_seed(self) -> _Stage:
        import numpy as np

        np.random.seed(42)
        return _Stage.SYNTH_DATA

    def _st_synth(self) -> _Stage:
        num_points = self.n
        bit_length = 10
        e = [random.randint(0, 2 ** bit_length - 1)]
        s = self.d
        self.ctx['data'] = [e * s for _ in range(num_points)]
        return _Stage.INDEX_BUILD

    def _st_index(self) -> _Stage:
        from preprocessing import create

        data = self.ctx['data']
        tree = create(data)
        self.ctx['tree'] = tree
        self.ctx['plain_tree'] = tree
        return _Stage.KNN_WARMUP

    def _st_knn(self) -> _Stage:
        from queryprocessing import height_of_binary_tree

        tree = self.ctx['tree']
        data = self.ctx['data']
        print('Index is built.')
        self.ctx['tree_height'] = height_of_binary_tree(tree)
        z = len(data[0])
        query_point = [0] * z
        self.ctx['query_point'] = query_point
        tree.search_knn(query_point, 3)
        return _Stage.OUTSOURCE

    def _st_outsource(self) -> _Stage:
        pub = self.ctx['public_key']
        tree = self.ctx['tree']
        if self.ctx['pairing_outsource']:
            from pairing_context import init_pairing_hybrid_default
            from preprocessing import DO_outsource_coordinates_pairing

            init_pairing_hybrid_default()
            self.ctx['tree'] = DO_outsource_coordinates_pairing(tree)
        else:
            from preprocessing import DO_outsource_to_server

            self.ctx['tree'] = DO_outsource_to_server(tree, pub)
        return _Stage.ROOT_HASH

    def _st_hash(self) -> _Stage:
        from queryprocessing import compute_hash_recursive

        self.ctx['Processed_Root_Hash'] = compute_hash_recursive(self.ctx['tree'])
        return _Stage.USER_REQUEST

    def _st_user_req(self) -> _Stage:
        from preprocessing import User_send_query_request

        User_send_query_request(self.ctx['query_point'], self.ctx['public_key'])
        return _Stage.CLOUD

    def _st_cloud(self) -> _Stage:
        from queryprocessing import Cloud_Processing

        qp = self.ctx['query_point']
        tree = self.ctx['tree']
        proc_hash = self.ctx['Processed_Root_Hash']
        th = self.ctx['tree_height']
        result = Cloud_Processing(qp, tree, self.k, proc_hash, th)
        self.ctx['cloud_result'] = result
        return _Stage.VERIFY

    def _st_verify(self) -> _Stage:
        from queryprocessing import check_result_soundness_completeness

        result_set_final, non_result_set, T, VO_Tree_Root, Processed_Root_Hash, tree = self.ctx['cloud_result']
        check_result_soundness_completeness(
            non_result_set, result_set_final, VO_Tree_Root, T, Processed_Root_Hash
        )
        self.ctx['Processed_Root_Hash'] = Processed_Root_Hash
        self.ctx['tree'] = tree
        return _Stage.DONE


def run_spk_pipeline(
    number_of_points: int,
    k: int,
    d: int,
    _g: Optional[Dict[str, Any]] = None,
) -> None:
    """
    Run the full SPK demo pipeline. Optional _g is the caller module globals dict
    (pass ``sys.modules[__name__].__dict__`` from main) so legacy ``data`` / ``tree`` /
    ``plain_tree`` bindings stay on the same module object as before.
    """
    orch = _SpkOrchestrator(number_of_points, k, d)
    orch.run()

    if _g is not None:
        _g['data'] = orch.ctx.get('data')
        _g['tree'] = orch.ctx.get('tree')
        _g['plain_tree'] = orch.ctx.get('plain_tree')
