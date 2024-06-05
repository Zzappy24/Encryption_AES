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
        assert msg == message_decrypt, "le message obtenue n'est pas le message initiale"
        print("message decrypt with success")

    def test_pipeline(self):
        msg = "je suis un password"
        key = generate_AES_Key()
        message_encrypt = encrypt_AES_GCM(msg, key)
        save_encrypt_message(message_encrypt, "./test/encryptedMessage.txt")
        message_encrypt_read = read_file("./test/encryptedMessage.txt")
        message_decrypt = decrypt_AES_GCM(message_encrypt_read, key)
        assert msg == message_decrypt, "le message obtenue n'est pas le message initiale"
        print("message decrypt with success")


if __name__ == '__main__':
    unittest.main()
