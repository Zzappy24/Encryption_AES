import json
from typing import Tuple, Any

from Crypto.Cipher import AES
import os
import binascii
import sys


def generate_AES_Key() -> bytes:
    secretKey: bytes = os.urandom(32)
    return secretKey


def hex_to_string(secretKey: bytes) -> str:
    return binascii.hexlify(secretKey).decode()


def save_key(key: bytes, path: str) -> None:
    with open(path, "w") as f:
        keyStr = hex_to_string(key)
        keyData = {"key": f"{keyStr}"}
        json.dump(keyData, f)


def encrypt_AES_GCM(msg: str | bytes, secretKey: str | bytes) -> tuple[str, str, str]:
    if type(secretKey) is str:
        secretKey = string_to_hex(secretKey)
    if type(msg) is str:
        msg = msg.encode('utf-8')
    aesCipher = AES.new(secretKey, AES.MODE_GCM)
    ciphertext, authTag = aesCipher.encrypt_and_digest(msg)
    encryptedMsg = ciphertext, aesCipher.nonce, authTag
    return msg_decode(encryptedMsg)


def msg_decode(encryptedMsg: tuple[bytes, bytes | bytearray | memoryview, bytes]) -> tuple[str, str, str]:
    encryptedMsg = (
        binascii.hexlify(encryptedMsg[0]).decode('utf-8'), binascii.hexlify(encryptedMsg[1]).decode('utf-8'),
        binascii.hexlify(encryptedMsg[2]).decode('utf-8')
    )
    return encryptedMsg


def msg_encode(encryptedMsg: tuple[str, str, str]) -> tuple[bytes, bytes, bytes]:
    encryptedMsg = (
        binascii.unhexlify(encryptedMsg[0]), binascii.unhexlify(encryptedMsg[1]), binascii.unhexlify(encryptedMsg[2])
    )
    return encryptedMsg


def save_encrypt_message(encryptedMsg: tuple[str, str, str], path: str) -> None:
    encryptedData = {'encryptMsg': {
        'ciphertext': encryptedMsg[0],
        'aesIV': encryptedMsg[1],
        'authTag': encryptedMsg[2]
    }}
    with open(path, "w") as f:
        json.dump(encryptedData, f)


def string_to_hex(valueString: str) -> bytes:
    valueBytes: bytes = bytes.fromhex(valueString)
    return valueBytes


def read_file(path: str) -> tuple[Any, Any, Any]:
    with open(path, "r") as file:
        encryptMsg = json.load(file)["encryptMsg"]
        encryptMsg = encryptMsg["ciphertext"], encryptMsg["aesIV"], encryptMsg["authTag"]
        return encryptMsg


def decrypt_AES_GCM(encryptedMsg: [str, str, str], secretKey) -> str:
    if type(secretKey) is str:
        secretKey = string_to_hex(secretKey)
    encryptedMsg = msg_encode(encryptedMsg)
    ciphertext = encryptedMsg[0]
    nonce = encryptedMsg[1]
    authTag = encryptedMsg[2]

    aesCipher = AES.new(secretKey, AES.MODE_GCM, nonce)
    plaintext = aesCipher.decrypt_and_verify(ciphertext, authTag)
    return plaintext.decode('utf-8')
