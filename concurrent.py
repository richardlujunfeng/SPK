from phe import paillier  
from concurrent.futures import ThreadPoolExecutor, as_completed  

public_key, private_key = paillier.generate_paillier_keypair()  

numbers = [10, 20, 30, 40, 50]  

def encrypt_number(num):  
    return public_key.encrypt(num)  

def decrypt_number(encrypted_num):  
    return private_key.decrypt(encrypted_num)  

with ThreadPoolExecutor() as executor:  

    future_to_num = {executor.submit(encrypt_number, num): num for num in numbers}  
    encrypted_numbers = []  
    for future in as_completed(future_to_num):  
        encrypted_numbers.append(future.result())  

 
encrypted_sum = sum(encrypted_numbers)  

with ThreadPoolExecutor() as executor:  
    future_to_enc_num = {executor.submit(decrypt_number, encrypted_sum): encrypted_sum}  
    decrypted_sum = future_to_enc_num.popitem()[1].result()  

print("Encrypted Numbers:", encrypted_numbers)  
print("Decrypted Sum:", decrypted_sum)