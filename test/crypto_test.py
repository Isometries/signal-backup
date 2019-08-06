import unittest
import sys
import os
#really ugly path manipulation
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))) 
from crypto.decryption_stream import DecryptionStream

class TestDecryption(unittest.TestCase):

    def test_decrpytion(self):
        iv = b'1234567891234567'
        passphrase = "Jimmy buttwiffff"
        test_data = self.read_file("test_data.bin")
        correct_output = self.read_file("correct_test.dat")
        output = b''

        decrypt_stream = DecryptionStream(passphrase, iv)
        decrypt_stream.cipher_key = b"Jimmy buttwiffff" #very hacky, but needed to bypass the hasing algo
        decrypt_stream.read(test_data)
        output = decrypt_stream.decrypt()
        with open("test_output.bin", 'wb') as f:
            f.write(output)
        self.assertEqual(correct_output, output)

    def read_file(self, location):
        test_data = b''
        with open(location, 'rb') as f:
            test_data = f.read()
        return test_data

if __name__ == "__main__":
    unittest.main()