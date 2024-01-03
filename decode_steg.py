import numpy as np
import PIL.Image
import os

from Aes import *
from master import verify_master_password

def decryption(file_name):
    pwd = input('Enter Password: ')

    ciphered_message = dec_steganography(file_name)

    try:
        original = AESCipher(pwd).decrypt(ciphered_message).decode('utf-8')
    except:
        print("Password could not be verified. Please enter the correct password.")
        return None

    print("Your secret message:", original)
    
def dec_steganography(file_name):
    image = PIL.Image.open(file_name, 'r')
    img_arr = np.array(list(image.getdata()))

    channels = 4 if image.mode == "RGBA" else 3

    pixels = img_arr.size // channels

    secret_bits = ''.join([bin(channels)[-1] for pixels in img_arr for channels in pixels])
    secret_bytes = [secret_bits[i:i+8] for i in range(0, len(secret_bits), 8)]

    secret_message = bytes(int(byte, 2) for byte in secret_bytes)

    stop_indicator = b"$STOP$"

    if stop_indicator in secret_message:
        binary_message = secret_message[:secret_message.index(stop_indicator)]
        message = bytes(int(binary_message[i:i+8], 2) for i in range(0, len(binary_message), 8))
        return message
    else:
        print("Not found")

def check_file_exists(filename):
    file_path = os.path.join(os.getcwd(), filename)
    if not os.path.exists(file_path):
        print(f"The file '{filename}' does not exist in the current directory.")
        exit(1)

if __name__ == "__main__":
    input_master_password = input("Enter master password: ") 
    if verify_master_password(input_master_password):
        file_name = input("Enter name of file you want to decrypt: ")
        check_file_exists(file_name)
        decryption(file_name)