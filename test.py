import unittest
import json
import time
from function import generate_AES_Key, encrypt_AES_GCM, decrypt_AES_GCM, save_key, save_encrypt_message, read_file
import encrypt_main
import decrypt_main


class TestAES(unittest.TestCase):

    def test_encrypt_decrypt(self):
        msg = "je suis un password"
        key = generate_AES_Key()
        message_encrypt = encrypt_AES_GCM(msg, key)
        message_decrypt = decrypt_AES_GCM(message_encrypt, key)
        assert msg == message_decrypt, "le message obtenu n'est pas le message initial"

    def test_pipeline(self):
        msg = "je suis un password"
        key = generate_AES_Key()
        message_encrypt = encrypt_AES_GCM(msg, key)
        save_encrypt_message(message_encrypt, "test/message.json")
        message_encrypt_read = read_file("test/message.json")
        message_decrypt = decrypt_AES_GCM(message_encrypt_read, key)
        assert msg == message_decrypt, "le message obtenu n'est pas le message initial"


if __name__ == '__main__':
    unittest.main()
