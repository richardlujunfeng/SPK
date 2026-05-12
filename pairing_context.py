from __future__ import annotations
from typing import Optional
from pairing_proxy_access import KeyHierarchy, keys_generate_demo
_pairing_hierarchy: Optional[KeyHierarchy] = None

def init_pairing_hybrid_default(kh: Optional[KeyHierarchy]=None) -> KeyHierarchy:
    global _pairing_hierarchy
    _pairing_hierarchy = kh or keys_generate_demo()
    return _pairing_hierarchy

def get_pairing_hierarchy() -> KeyHierarchy:
    global _pairing_hierarchy
    if _pairing_hierarchy is None:
        _pairing_hierarchy = keys_generate_demo()
    return _pairing_hierarchy

def reset_pairing_hybrid() -> None:
    global _pairing_hierarchy
    _pairing_hierarchy = None
