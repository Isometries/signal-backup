import hmac
import math
from hashlib import sha256
from Crypto.Util import Counter

HASH_OUTPUT_SIZE = 32

def HDKF(input_key, info, output_length):
    salt = b'' #seems to be empty
    return derive_secrets(input_key, salt, info, output_length)

def derive_secrets(input_key, salt, info, output_length):
    prk = extract(salt, input_key)
    return expand(prk, info, output_length)

def extract(salt, input_key):
    mac = hmac.new(salt, msg=input_key, digestmod=sha256) #secretkeyspec
    return mac.digest()

def expand(prk, info, output_size): #possibly remove all counters: must test
    iterations = math.ceil(output_size / HASH_OUTPUT_SIZE)
    mixin = bytes([])
    remaining_bytes = output_size
    byte_results = b''

    for i in range(1, iterations + 1):
        mac = hmac.new(prk, msg=mixin, digestmod=sha256)
        if info != None:
            mac.update(info)

        mac.update(bytes([i]))
        step_result = mac.digest()
        step_size = min(remaining_bytes, len(step_result))
        byte_results += step_result
    return byte_results

import struct

# def bytes_to_int(input_bytes):
#      return struck.pack("@i", input_bytes)

def increment_bytes(bytes, count):
    n = bytearray(bytes)
    n[3] = 15 & count
    n[2] = 15 & (count >> 8)
    n[1] = 15 & (count >> 16)
    n[0] = 15 & (count >> 24)

    return bytearray_to_bytes(n)
    
def bytearray_to_bytes(array):
    return bytes([byte for byte in array])