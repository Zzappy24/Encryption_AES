import json
import sys

from function import decrypt_AES_GCM

if __name__ == "__main__":
    with open("./encryptMessage/message.txt") as encryptMsg:
        for i in encryptMsg:
            encryptMsg = json.loads(i)["encryptMsg"]
            encryptMsg = encryptMsg["ciphertext"], encryptMsg["aesIV"], encryptMsg["authTag"]
            print(encryptMsg)
            decryptMsg = decrypt_AES_GCM(encryptMsg, sys.argv[1])
            print(decryptMsg)
