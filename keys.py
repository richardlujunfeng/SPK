# keys.py  
from phe import paillier  

# 生成密钥对并保存  
public_key, private_key = paillier.generate_paillier_keypair()  

# 可选: 将密钥导出为字符串形式以便存储  
def get_private_key():  
    return private_key  

def get_public_key():  
    return public_key  