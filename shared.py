import hashlib
from main import *
from keys import get_private_key, get_public_key
import preprocessing
from storage import *
import numpy as np
from phe import paillier


def secure_paillier_distance_sq_encrypted(coord_plain_with_shift, query_pv_plain, query_pv_shift):
    public_key = get_public_key()
    pv = int(query_pv_plain) + int(query_pv_shift)
    tmp2 = pv >> 32
    tmp3 = pv & 4294967295
    distance_result = tmp3 * (coord_plain_with_shift - tmp2) * (coord_plain_with_shift - tmp2)
    return public_key.encrypt(distance_result)

def Secure_distance_compute(node_data, query_point, perturb_plain_offset=0, query_pv_plain=None, query_pv_shift=0):
    private_key = get_private_key()
    public_key = get_public_key()
    from pairing_proxy_access import PairingStoredCoord
    from pairing_context import get_pairing_hierarchy
    if isinstance(node_data, PairingStoredCoord):
        kh = get_pairing_hierarchy()
        from pairing_proxy_access import decrypt_coordinate
        tmp1 = decrypt_coordinate(node_data.ct, kh)
        tmp1 = (int(tmp1) + int(perturb_plain_offset)) % kh.params.q
    else:
        tmp1 = private_key.decrypt(node_data)
    if query_pv_plain is not None:
        return secure_paillier_distance_sq_encrypted(tmp1, query_pv_plain, query_pv_shift)
    from storage import decrypt_and_unpack
    tmp2, tmp3 = decrypt_and_unpack(query_point)
    distance_result = tmp3 * (tmp1 - tmp2) * (tmp1 - tmp2)
    distance_result = public_key.encrypt(distance_result)
    return distance_result

def safe_encrypted_subtract(encrypted_a, encrypted_b, public_key, private_key):
    import os
    if os.environ.get('SPK_LEGACY_SAFE_SUBTRACT', '').lower() in ('1', 'true', 'yes'):
        try:
            a_value = private_key.decrypt(encrypted_a)
            b_value = private_key.decrypt(encrypted_b)
            if abs(a_value) > 1000000000.0 or abs(b_value) > 1000000000.0:
                scale_factor = 0.001
                new_encrypted_a = public_key.encrypt(a_value * scale_factor)
                new_encrypted_b = public_key.encrypt(b_value * scale_factor)
                result = new_encrypted_a - new_encrypted_b
                final_result = private_key.decrypt(result) / scale_factor
                return public_key.encrypt(final_result)
            return encrypted_a - encrypted_b
        except OverflowError:
            return None
        except Exception:
            return None
    try:
        return encrypted_a - encrypted_b
    except Exception:
        return None

def safe_compare_encrypted(dec_a_sub_b, N):
    try:
        half_N = N // 2
        if isinstance(dec_a_sub_b, float):
            dec_a_sub_b = int(dec_a_sub_b)
        return abs(dec_a_sub_b) > half_N
    except OverflowError:
        return False
    except Exception:
        return False

def compare_encrypted_values(dec_a_sub_b, N):
    try:
        dec_a_sub_b = int(dec_a_sub_b)
        N = int(N)
        half_N = N >> 1
        abs_diff = abs(dec_a_sub_b)
        if abs_diff > half_N:
            return True
        return False
    except Exception:
        return False

def Secure_integer_compare_protocol(a, b):
    public_key = get_public_key()
    private_key = get_private_key()
    N = public_key.n
    a_double = a + a
    b_double = b + b + 1
    a_sub_b = safe_encrypted_subtract(a_double, b_double, public_key, private_key)
    r = random.randint(0, N // 4)
    if a_sub_b is None:
        return None
    try:
        if a_sub_b == 'add':
            return a_sub_b + r
        elif a_sub_b == 'sub':
            return a_sub_b - r
    except Exception:
        return None
    dec_a_sub_b = private_key.decrypt(a_sub_b)
    result = compare_encrypted_values(abs(dec_a_sub_b), N)
    if result:
        res = public_key.encrypt(0)
    else:
        res = public_key.encrypt(1)
    return res

def Secure_pop_maximum_protocol(result_queue_set, non_result_queue_set, node_data, T, k):
    tmp = result_queue_set.pop()
    queue_tmp_max = -1
    for i in range(k):
        result_point = result_queue_set.popleft()
        if result_point.distance > tmp.distance:
            result_queue_set.append(tmp)
            if tmp.distance > queue_tmp_max:
                T = tmp.distance
                queue_tmp_max = tmp.distance
            else:
                T = result_point.distance
            tmp = result_point
        else:
            result_queue_set.append(result_point)
    if tmp:
        non_result_queue_set.append(tmp)
    return (result_queue_set, non_result_queue_set, T)

def compute_prune_object_digest(node, combined_result):
    if node is None:
        return combined_result
    combined_result = compute_prune_object_digest(node.left, combined_result)
    combined_result = compute_prune_object_digest(node.right, combined_result)
    if node.data:
        if combined_result:
            combined_result = str(combined_result) + str(node.data)
            tree_root_hash = hashlib.sha256(str(combined_result).encode())
            combined_result = tree_root_hash.hexdigest()
        else:
            combined_result = node.data
    return combined_result
