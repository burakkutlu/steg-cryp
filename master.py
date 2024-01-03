import json
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import os

def generate_salt():
    return get_random_bytes(16)

def hash_password(password, salt):
    hashed_password = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return hashed_password

def encrypt_file(master_password, data):
    key = hashlib.sha256(master_password.encode()).digest()
    cipher = AES.new(key, AES.MODE_CBC)
    serialized_data = json.dumps(data).encode()
    ciphertext = cipher.encrypt(pad(serialized_data, AES.block_size))
    return cipher.iv + ciphertext

def decrypt_file(master_password, ciphertext):

    key = hashlib.sha256(master_password.encode()).digest()
    iv = ciphertext[:AES.block_size]
    ciphertext_yeni = ciphertext[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = cipher.decrypt(ciphertext_yeni)
    unpadded_data = unpad(decrypted_data, AES.block_size)
    return json.loads(unpadded_data.decode())

def save_master_password():
    clear_user_data_file()
    master_password = input("Enter Master password: ")
    salt = generate_salt()
    hashed_master_password = hash_password(master_password, salt)
    data = {
        'hashed_master_password': hashed_master_password.hex(),
        'salt': salt.hex()
    }

    with open('master.enc', 'ab') as file:
        encrypted_data = encrypt_file(master_password, data)
        file.write(encrypted_data)
        print("master password saved successfully.")

def verify_master_password(input_password):
    with open('master.enc', 'rb') as file:
        encrypted_data = file.read()
        try:
            stored_data = decrypt_file(input_password, encrypted_data)

            stored_hashed_master_password = stored_data.get('hashed_master_password')
            stored_salt = bytes.fromhex(stored_data.get('salt'))

            input_password_hashed = hash_password(input_password, stored_salt).hex()

            return input_password_hashed == stored_hashed_master_password
        except:
            print("Master password could not be verified. Please enter the correct password.")
            return False


def print_user_data(master_password):
    with open('master.enc', 'rb') as file:
        encrypted_data = file.read()
        decrypted_data = decrypt_file(master_password, encrypted_data)
        print("Decrypted User Data:", decrypted_data)

def clear_user_data_file():
    with open('master.enc', 'wb') as file:
        file.truncate(0)


if __name__ == "__main__":
    #master_password = "admin"
    save_master_password()
    #os.remove("master.py")
