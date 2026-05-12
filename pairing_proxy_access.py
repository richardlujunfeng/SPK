from __future__ import annotations
import secrets
from dataclasses import dataclass
from typing import Callable, Dict, FrozenSet, Optional

from phe.util import powmod

Int = int

@dataclass
class PairingParams:
    r: Int
    q: Int
    g: Int
    k_pair: Int
    omega: Int

    def omega_pow(self, exp: Int) -> Int:
        exp = exp % self.q
        return powmod(self.omega, exp, self.r)

    def g_pow(self, exp: Int) -> Int:
        exp = exp % self.q
        return powmod(self.g, exp, self.r)

    def pair_from_exponents(self, u: Int, v: Int) -> Int:
        return self.g_pow(self.k_pair * u * v % self.q)

    def gt_mul(self, a: Int, b: Int) -> Int:
        return a * b % self.r

    def gt_inv(self, x: Int) -> Int:
        return powmod(x, self.r - 2, self.r)

    def decode_message_bruteforce(self, gt_elem: Int, max_m: Optional[Int]=None) -> Int:
        bound = max_m if max_m is not None else self.q
        cur = 1
        for m in range(bound):
            if cur == gt_elem % self.r:
                return m
            cur = cur * self.omega % self.r
        raise ValueError('discrete log decode failed — increase subgroup or pass max_m')

def _derive_subgroup_generator(r: Int, q: Int) -> Int:
    cofactor = (r - 1) // q
    for _ in range(256):
        h = secrets.randbelow(r - 3) + 2
        g = powmod(h, cofactor, r)
        if g != 1 and powmod(g, q, r) == 1:
            return g
    raise RuntimeError('failed to sample subgroup generator')

def pair_params_generate_toy(q_bits: int=48) -> PairingParams:
    assert q_bits >= 16
    while True:
        q = secrets.randbits(q_bits) | 1 << q_bits - 1 | 1
        if q.bit_length() != q_bits:
            continue
        if powmod(2, q - 1, q) != 1:
            continue
        for offset in range(2, 2000, 2):
            r = q * offset + 1
            if r.bit_length() < q_bits + 4:
                continue
            if powmod(2, r - 1, r) != 1:
                continue
            g = _derive_subgroup_generator(r, q)
            k_pair = secrets.randbelow(q - 3) + 2
            omega = powmod(g, k_pair, r)
            return PairingParams(r=r, q=q, g=g, k_pair=k_pair % q, omega=omega)

def pair_params_generate_fixed_demo() -> PairingParams:
    q = 1009
    r = q * 4 + 1
    while powmod(2, r - 1, r) != 1:
        r += q * 2
    g = _derive_subgroup_generator(r, q)
    k_pair = 17 % q
    omega = powmod(g, k_pair, r)
    return PairingParams(r=r, q=q, g=g, k_pair=k_pair, omega=omega)

@dataclass
class PublicWire:
    params: PairingParams
    G2_pub: Int

@dataclass
class UserCredential:
    subject_id: str
    attrs: FrozenSet[str]
    issuance_tag: bytes
    dimension_scope: Optional[FrozenSet[int]] = None

@dataclass
class DOKeyMaterial:
    alpha: Int

@dataclass
class KeyHierarchy:
    params: PairingParams
    do: DOKeyMaterial
    public: PublicWire

def keys_generate(q_bits: int=48) -> KeyHierarchy:
    params = pair_params_generate_toy(q_bits)
    alpha = secrets.randbelow(params.q - 3) + 2
    G2_pub = params.g_pow(params.k_pair * alpha % params.q)
    return KeyHierarchy(params=params, do=DOKeyMaterial(alpha=alpha % params.q), public=PublicWire(params=params, G2_pub=G2_pub))

def keys_generate_demo() -> KeyHierarchy:
    params = pair_params_generate_fixed_demo()
    alpha = 313 % params.q
    G2_pub = params.g_pow(params.k_pair * alpha % params.q)
    return KeyHierarchy(params=params, do=DOKeyMaterial(alpha=alpha % params.q), public=PublicWire(params=params, G2_pub=G2_pub))

@dataclass
class Ciphertext:
    A: Int
    B: Int

@dataclass
class PairingStoredCoord:
    ct: Ciphertext

def encrypt_coordinate(pk: PublicWire, plaintext_m: Int, rho: Optional[Int]=None) -> Ciphertext:
    params = pk.params
    rho = rho if rho is not None else secrets.randbelow(params.q - 3) + 2
    rho %= params.q
    A = params.g_pow(rho)
    omega_m = params.omega_pow(plaintext_m % params.q)
    mask = powmod(pk.G2_pub, rho, params.r)
    B = omega_m * mask % params.r
    return Ciphertext(A=A, B=B)

def decrypt_coordinate(ct: Ciphertext, hierarchy: KeyHierarchy) -> Int:
    params = hierarchy.params
    alpha = hierarchy.do.alpha % params.q
    mask = powmod(ct.A, params.k_pair * alpha % params.q, params.r)
    omega_m = ct.B * params.gt_inv(mask) % params.r
    return params.decode_message_bruteforce(omega_m)

@dataclass(frozen=True)
class AccessPolicy:
    required_attrs: FrozenSet[str]
    allowed_dimensions: Optional[FrozenSet[int]] = None

def policy_satisfied(policy: AccessPolicy, creds: UserCredential) -> bool:
    if not policy.required_attrs <= creds.attrs:
        return False
    if policy.allowed_dimensions is None:
        return True
    if creds.dimension_scope is None:
        return False
    return creds.dimension_scope <= policy.allowed_dimensions

def create_do_pre_issuer(hierarchy: KeyHierarchy):

    def issuer(policy: AccessPolicy, user: UserCredential, *, epsilon: Int, rerandom_rho: bool=True) -> Optional[Callable[[Ciphertext], Ciphertext]]:
        return issue_proxy_reencrypt_capability(hierarchy, policy, user, epsilon=epsilon, rerandom_rho=rerandom_rho)
    return issuer

def issue_proxy_reencrypt_capability(hierarchy: KeyHierarchy, policy: AccessPolicy, user: UserCredential, *, epsilon: Int, rerandom_rho: bool=True) -> Optional[Callable[[Ciphertext], Ciphertext]]:
    if not policy_satisfied(policy, user):
        return None
    params = hierarchy.params
    eps_internal = int(epsilon) % params.q

    def _pre_transform(ct: Ciphertext) -> Ciphertext:
        B_shift = ct.B * params.omega_pow(eps_internal) % params.r
        if not rerandom_rho:
            return Ciphertext(A=ct.A, B=B_shift)
        nu = secrets.randbelow(params.q - 3) + 2
        A_new = ct.A * params.g_pow(nu) % params.r
        mask_boost = powmod(hierarchy.public.G2_pub, nu, params.r)
        B_new = B_shift * mask_boost % params.r
        return Ciphertext(A=A_new, B=B_new)
    return _pre_transform

def expose_capability_metadata(user: UserCredential, policy: AccessPolicy) -> Dict[str, object]:
    return {'subject': user.subject_id, 'attrs': sorted(user.attrs), 'policy': sorted(policy.required_attrs), 'closure_kind': 'PRE_eps_rerand'}
__all__ = ['AccessPolicy', 'Ciphertext', 'PairingStoredCoord', 'DOKeyMaterial', 'KeyHierarchy', 'PairingParams', 'PublicWire', 'UserCredential', 'create_do_pre_issuer', 'decrypt_coordinate', 'encrypt_coordinate', 'expose_capability_metadata', 'issue_proxy_reencrypt_capability', 'keys_generate', 'keys_generate_demo', 'pair_params_generate_fixed_demo', 'pair_params_generate_toy', 'policy_satisfied']
if __name__ == '__main__':
    kh = keys_generate_demo()
    pk = kh.public
    m = 42
    ct = encrypt_coordinate(pk, m)
    assert decrypt_coordinate(ct, kh) == m
    alice = UserCredential(subject_id='alice', attrs=frozenset({'kd.query', 'tenant.A'}), issuance_tag=b't1', dimension_scope=frozenset({0, 1}))
    pol_ok = AccessPolicy(required_attrs=frozenset({'kd.query'}), allowed_dimensions=frozenset({0, 1, 2}))
    pol_fail = AccessPolicy(required_attrs=frozenset({'kd.admin'}))
    pre_denied = issue_proxy_reencrypt_capability(kh, pol_fail, alice, epsilon=7)
    assert pre_denied is None
    eps = 5
    do_issue = create_do_pre_issuer(kh)
    pre_ok = do_issue(pol_ok, alice, epsilon=eps, rerandom_rho=True)
    assert pre_ok is not None
    ct2 = pre_ok(ct)
    assert decrypt_coordinate(ct2, kh) == (m + eps) % kh.params.q
    bob = UserCredential(subject_id='bob', attrs=frozenset({'kd.query'}), issuance_tag=b't2', dimension_scope=frozenset({0, 3}))
    pol_dim = AccessPolicy(required_attrs=frozenset({'kd.query'}), allowed_dimensions=frozenset({0, 1}))
    assert issue_proxy_reencrypt_capability(kh, pol_dim, bob, epsilon=1) is None
