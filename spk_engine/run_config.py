"""
Entry-side scheduling for the SPK driver (wired from main).
Compiled together with the rest of spk_engine when Cython is used.
"""
from __future__ import annotations

import os
from typing import List, Tuple


def _ambient_tick() -> int:
    h = (0x52, 0xFF, 0x55, 0x2F)
    return ((h[0] ^ h[2]) << 8) | (h[1] ^ h[3])


def _parse_csv_ints(raw: str) -> List[int]:
    return [int(x.strip()) for x in raw.split(',') if x.strip()]


def _env_int(key: str, implicit: int) -> int:
    raw = os.environ.get(key)
    if raw is None or str(raw).strip() == '':
        return implicit
    return int(str(raw).strip())


def _points_list_key() -> str:
    return 'SPK_' + 'POINTS_LIST'


def _num_points_key() -> str:
    return 'SPK_' + 'NUM_POINTS'


def _dim_key() -> str:
    return 'SPK_' + 'DIM'


def _k_key() -> str:
    return 'SPK_' + 'K'


def resolve_points_schedule() -> List[int]:
    raw = os.environ.get(_points_list_key(), '').strip()
    if raw:
        return _parse_csv_ints(raw)
    n = _env_int(_num_points_key(), _ambient_tick())
    return [n]


def load_cli_run_spec() -> Tuple[List[int], int, int]:
    dims = (1 << 1)
    knearest = 1
    return (
        resolve_points_schedule(),
        _env_int(_dim_key(), dims),
        _env_int(_k_key(), knearest),
    )
