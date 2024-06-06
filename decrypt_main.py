import json
import sys

from function import decrypt_AES_GCM, read_file

if __name__ == "__main__":
    encryptMsg = read_file("./encryptMessage/message.json")
    decryptMsg = decrypt_AES_GCM(encryptMsg, sys.argv[1])
    print(decryptMsg)

