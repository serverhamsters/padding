#!/usr/bin/python3

from Crypto import Random
from Crypto.Cipher import DES
import ghelper as gh

class InvalidPadding(Exception):
    pass

def pad_ansix923(message_bstr, block_size):
    '''
    ANSI X9.23
    https://en.wikipedia.org/wiki/Padding_(cryptography)#ANSI_X9.23
    '''
    i = block_size - (len(message_bstr) % block_size)
    if i == 0:
        # add a full padding block
        return message_bstr + b"\x00" * (block_size - 1) + bytes([block_size])
    else:
        return message_bstr + (b"\x00" * (i - 1)) + bytes([i])

def pad_pkcs7(message_bstr, block_size):
    '''
    PKCS#5 and PKCS#7 padding
    https://tools.ietf.org/html/rfc5652#section-6.3
    https://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS#5_and_PKCS#7
    '''
    i = block_size - (len(message_bstr) % block_size)
    if i == 0:
        # add a full padding block
        return message_bstr + (bytes([block_size]) * block_size)
    else:
        return message_bstr + (bytes([i]) * i)

def remove_pkcs7(message_bstr, block_size):
    last_byte = message_bstr[-1]

    if last_byte > block_size:
        raise InvalidPadding("Last byte is bigger than the block size")
    
    if (bytes([last_byte]) * last_byte) != message_bstr[-last_byte:]:
        raise InvalidPadding("Padding bytes don't match")
    
    return message_bstr[:-last_byte]

def encrypt_DES(key, message_bstr, iv=None, padding_f=pad_pkcs7):
    '''
    Encryptes with DES CBC with PKCS#7 padding.
    Prepends the IV to the encrypted data.
    A random IV will be generated if no IV is given.
    '''
    if iv is None:
        iv = Random.new().read(DES.block_size)

    padded_msg = pad_pkcs7(message_bstr, DES.block_size)
    cipher_des = DES.new(key, DES.MODE_CBC, iv)
    cipher_text = cipher_des.encrypt(padded_msg)
    return iv + cipher_text

def decrypted_DES(key, encrypted_bstr):
    '''
    Decrypts DES CBC, expects the IV as the first block. Removes PKCS#7 padding.
    '''
    iv = encrypted_bstr[:DES.block_size]
    encrypted_msg = encrypted_bstr[DES.block_size:]
    cipher_des = DES.new(key, DES.MODE_CBC, iv)
    decrypted_message = cipher_des.decrypt(encrypted_msg)
    print(gh.bstr2hex(decrypted_message))
    return remove_pkcs7(decrypted_message, DES.block_size)


key = b'c\xf0\x14\xdf\xf9\x94\xea\x8d' # Random.new().read(DES.key_size)

message = "Hello World! 🇧🇪 ❤️ 💀"
message_bstr = message.encode("UTF-8")

encrypted_bstr = encrypt_DES(key, message_bstr)
decrypted_bstr = decrypted_DES(key, encrypted_bstr)
decrypted_message = decrypted_bstr.decode("UTF-8")
print(message)
print("#IV             #MESSAGE                                          " + \
      "                #PADDING")
print(' ' * 16 + gh.bstr2hex(message_bstr).replace(' ', ''))
print(gh.bstr2hex(encrypted_bstr).replace(' ', ''))
print(' ' * 16 + gh.bstr2hex(decrypted_bstr).replace(' ', ''))
print(decrypted_message)
"""
# Padding test code
ansix = b"In ANSI X9.23, between 1 and 8 bytes are always added as padding."
for i in range(65):
    s = ansix[:i]
    print("{:2d} {}".format(i, gh.bstr2hex(pad_ansix923(s, 8)).replace(" ","")))
    
    # Try removing faulty padding
    try:
        print("{:2d} {}".format(i, gh.bstr2hex(remove_pkcs7(pad_ansix923(s, 8),\
            8)).replace(" ","")))
    except InvalidPadding as e:
        print(e)


ansix = b"The padding can be removed unambiguously since all input is padded"
for i in range(66):
    s = ansix[:i]
    print("{:2d} {}".format(i, gh.bstr2hex(pad_pkcs7(s, 8)).replace(" ","")))
    print("{:2d} {}".format(i, gh.bstr2hex(remove_pkcs7(pad_pkcs7(s, 8), 8)).\
        replace(" ","")))
"""
s = b"The padding can be removed unambiguously since all input is padded"[:5]
print("{}".format(gh.bstr2hex(pad_pkcs7(s, 8)).replace(" ","")))
print("{}".format(gh.bstr2hex(remove_pkcs7(pad_pkcs7(s, 8), 8)).\
    replace(" ","")))

encrypted = encrypt_DES(key, s)
print(encrypted)

def oracle(encrypted):
    '''
    returns whether the padding is valid or not.
    '''
    global key
    try:
        decrypted_DES(key, encrypted)
        return True
    except InvalidPadding as e:
        #print(e)
        return False

print(oracle(encrypted))
modified_enc = encrypted

for i in range(1, 0xFF):
    modified_enc = encrypted[:7] + bytes([encrypted[7] ^ i]) + encrypted[8:]
    is_valid_pad = oracle(modified_enc)
    print(gh.bstr2hex(modified_enc))
    print("8th byte 0x{:02X} {:08b}, xor 0x{:02X} {:08b}, valid pad: {}".format(
        modified_enc[7],
        modified_enc[7],
        i,
        i,
        is_valid_pad
    ))
    if (is_valid_pad):
        # calculate plain text
        last_xor_val = i
        plain_byte = i ^ 0x01
        print("Plain byte: 0x{:02x} {:08b}".format(plain_byte, plain_byte))
        break

# Possible optimization
# If this is the last block, and we know '03' is the last byte then we also
# know that the last 3 bytes are '03 03 03'. We could skip those if we wanted.
found_bytes = list()
found_bytes.append(plain_byte)

for i in range(1, 0xFF):
    modified_enc = encrypted[:6] + bytes([encrypted[6] ^ i]) + bytes([encrypted[7] ^ 0x01]) + encrypted[8:]
    is_valid_pad = oracle(modified_enc)
    print(gh.bstr2hex(modified_enc))
    print("8th modified byte 0x{:02X} {:08b}, Original: 0x{:02X} {:08b}".format(
        modified_enc[7],
        modified_enc[7],
        encrypted[7],
        encrypted[7],
    ))
    print("7th byte 0x{:02X} {:08b}, xor 0x{:02X} {:08b}, valid pad: {}".format(
        modified_enc[6],
        modified_enc[6],
        i,
        i,
        is_valid_pad
    ))
    if (is_valid_pad):
        # calculate plain text
        plain_byte = i ^ 0x02
        print("Last 2 bytes: 0x{:02X} 0x{:02X}".format(plain_byte, found_bytes[0]))
        break
    
found_bytes.append(plain_byte)

for i in range(0, 0xFF):
    modified_enc = encrypted[:5] + bytes([encrypted[5] ^ i]) + \
        bytes([encrypted[6] ^ 0x00]) +  \
        bytes([encrypted[7] ^ 0x00]) + encrypted[8:]
    is_valid_pad = oracle(modified_enc)
    print(gh.bstr2hex(modified_enc))
    print("8th modified byte 0x{:02X} {:08b}, Original: 0x{:02X} {:08b}".format(
        modified_enc[7],
        modified_enc[7],
        encrypted[7],
        encrypted[7],
    ))
    print("7th byte 0x{:02X} {:08b}, Original: 0x{:02X} {:08b}".format(
        modified_enc[6],
        modified_enc[6],
        encrypted[6],
        encrypted[6]
    ))
    print("6th byte 0x{:02X} {:08b}, xor 0x{:02X} {:08b}, valid pad: {}".format(
        modified_enc[5],
        modified_enc[5],
        i,
        i,
        is_valid_pad
    ))
    if (is_valid_pad):
        # calculate plain text
        plain_byte = i ^ 0x03
        print("Last 3 bytes: 0x{:02X} 0x{:02X} 0x{:02X}".format(plain_byte, \
            found_bytes[1], found_bytes[0]))
        break