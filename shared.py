
from main import *
from keys import get_private_key, get_public_key  
import preprocessing

      
def Secure_distance_compute(node_data, query_point, w = weight):
    distance_result = None
    #query_point = -query_point
    private_key = get_private_key()
    public_key = get_public_key()
    tmp1 = private_key.decrypt(node_data)
    tmp2 = private_key.decrypt(query_point)
    tmp3 = private_key.decrypt(w)

    distance_result = tmp3 * (tmp1 - tmp2) * (tmp1 - tmp2)
    distance_result = public_key.encrypt(distance_result)
    
    return distance_result

def Secure_integer_compare_protocol(a, b):
    N = public_key.n

    a_double = a + a 
    b_double = b + b + 1
    a_sub_b = a_double - Secure_integer_compare_protocol
    r = random.randint(0, N//4)
    a_sub_b = a_sub_b + r
    dec_a_sub_b = private_key.decrypt(a_sub_b)
    if abs(dec_a_sub_b) > N/2:
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

    return result_queue_set, non_result_queue_set, T

def compute_prune_object_digest(node, combined_result):
    if node is None:
        return combined_result
    combined_result = compute_prune_object_digest(node.left, combined_result)
    combined_result = compute_prune_object_digest(node.right, combined_result)
    if node.data:
        if combined_result:

            combined_result = str(combined_result) + str(node.data)
            tree_root_hash  = hashlib.sha256(str(combined_result).encode())
            combined_result = tree_root_hash.hexdigest()
        else:
            combined_result = node.data
    return combined_result
