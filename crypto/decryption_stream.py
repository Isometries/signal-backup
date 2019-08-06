#this class should be used soley for creating a decryption stream. A seperate stream
#should be created for parsing the protobuf
import hmac
from hashlib import sha256, sha512
from Crypto.Cipher import AES
from .crypto_utils import HDKF, increment_bytes
import Crypto.Util


BLOCK_SIZE = 128


class DecryptionStream():
    #possibly do something with hmac later - place holder for now
    def __init__(self, passphrase, iv):
        self.iv = iv
        self.data = None
        key = self.derive_key(passphrase, iv)
        derived = HDKF(key, b"Backup Export", 64)
        self.cipher_key = derived[:32]
        self.mac_key = derived[32::]
        self.count = 0
        self.mac = hmac.new(self.mac_key,
                            msg=None,
                            digestmod=sha256)

    def derive_key(self, passphrase, salt):
        digest = sha512()
        digest.update(self.iv)

        if " " in passphrase:
            passphrase = passphrase.replace(" ", "")

        passphrase_bytes = passphrase.encode()
        pass_hash = passphrase_bytes

        for i in range(250000):
            #possibly set up a progress counter here
            digest.update(pass_hash)
            digest.update(passphrase_bytes)
            pass_hash = digest.digest()
            digest = sha512() #seems the digest must be reset

        return pass_hash[:32]

    def decrypt(self): #can't store cipher as instance var because of counter
        self.increase_iv()
        iv_in_int = int.from_bytes(self.iv, byteorder='big')
        new_counter = Crypto.Util.Counter.new(BLOCK_SIZE, 
                                              initial_value=iv_in_int)
        cipher = AES.new(self.cipher_key,
                         AES.MODE_CTR,
                         counter=new_counter)

        print(self.cipher_key, iv_in_int)
        decrypted_bytes = cipher.decrypt(self.data)
        print(decrypted_bytes)
        self.clear_data()
        return decrypted_bytes

    def increase_iv(self):
        self.iv = increment_bytes(self.iv, self.count)
        self.count += 1

    def read(self, byte_buffer, length=None):
        if length != None:
            self.data += byte_buffer[:length]
        else:
            self.data = byte_buffer

    def clear_data(self):
        self.data = None
