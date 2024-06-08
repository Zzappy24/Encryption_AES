from function import encrypt_AES_GCM, save_encrypt_message
import sys

if __name__ == "__main__":
    encryptMsg = encrypt_AES_GCM(msg=b'test cryptage AES',
                                 secretKey=sys.argv[1])
    print(encryptMsg)
    save_encrypt_message(encryptMsg, "encryptMessage/message.json")
