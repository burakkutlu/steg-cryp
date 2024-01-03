import numpy as np
import PIL.Image
import os

from Aes import *
from master import verify_master_password

def encryption():
    message_to_hide = input("Enter the message you want to encrypt and hide: ")
    pwd = input('Enter Password: ')

    ciphered_message = AESCipher(pwd).encrypt(message_to_hide).decode('utf-8')

    return ciphered_message


def enc_steganography(file_name):

    image = PIL.Image.open(file_name, 'r')
    width, height = image.size
    img_arr = np.array(list(image.getdata()))

    if image.mode == "P":
        print("Not supported")
        exit(1)

    message_to_hide_enc = encryption()

    channels = 4 if image.mode == "RGBA" else 3
    pixels = img_arr.size // channels
    stop_indicator = "$STOP$"
    binary_message = ''.join(format(ord(byte), '08b') for byte in message_to_hide_enc)
    message_to_hide = binary_message + stop_indicator

    byte_message = ''.join(f"{ord(c):08b}" for c in message_to_hide)
    bits = len(byte_message)

    if bits > pixels:
        print("Not enough pixels")
        exit(1)
    else:
        index = 0
        for i in range(pixels):
            for j in range(0,3):
                if index < bits:
                    img_arr[i][j] = int(bin(img_arr[i][j])[2:-1] + byte_message[index], 2)
                    index += 1


    img_arr = img_arr.reshape(height, width, channels)
    result = PIL.Image.fromarray(img_arr.astype('uint8'), image.mode)
    result.save(file_name + ".enc", format="PNG")


def check_file_exists(filename):
    file_path = os.path.join(os.getcwd(), filename)

    if not os.path.exists(file_path):
        print(f"The file '{filename}' does not exist in the current directory.")
        exit(1)

if __name__ == "__main__":
    input_master_password = input("Enter master password: ") 
    if verify_master_password(input_master_password):
        file_name = input("Enter name of file you want to encrypt: ")
        check_file_exists(file_name)
        enc_steganography(file_name)
