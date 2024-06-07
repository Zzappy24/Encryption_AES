import json
from typing import Any
import logging
from Crypto.Cipher import AES
import os
import binascii

# Définition du décorateur de gestion des erreurs
def gestion_erreur_decorator(func):
    """
    Décorateur pour gérer les erreurs dans les fonctions.
    Loggue les erreurs et les relance.

    Args:
        func (callable): La fonction à décorer.

    Returns:
        callable: La fonction décorée avec gestion des erreurs.
    """
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except TypeError as e:
            logging.error(f"Erreur {type(e).__name__} dans la fonction {func.__name__}: {e}, possible erreur de type pour msg")
            raise
        except ValueError as e:
            logging.error(f"Erreur {type(e).__name__} dans la fonction {func.__name__}: {e}, possible erreur de key")
            raise
        except FileNotFoundError as e:
            logging.error(f"Erreur {type(e).__name__} dans la fonction {func.__name__}: {e}")
            raise
        except Exception as e:
            logging.error(f"Erreur inattendue {type(e).__name__} dans la fonction {func.__name__}: {e}")
            raise
    return wrapper



@gestion_erreur_decorator
def generate_AES_Key() -> bytes:
    """
    Génère une clé secrète AES de 256 bits.

    Returns:
        La clé secrète générée.
    """
    secretKey: bytes = os.urandom(32)
    return secretKey

@gestion_erreur_decorator
def hex_to_string(secretKey: bytes) -> str:
    """
    Convertit une clé secrète en chaîne hexadécimale.

    Args:
        secretKey (bytes): La clé secrète à convertir.

    Returns:
        La clé str en chaîne hexadécimale.
    """
    return binascii.hexlify(secretKey).decode()

@gestion_erreur_decorator
def save_key(key: bytes, path: str) -> None:
    """
    Sauvegarde une clé secrète dans un fichier JSON.

    Args:
        key (bytes): La clé secrète à sauvegarder.
        path (str): Le chemin du fichier de sauvegarde.
    """
    with open(path, "w") as f:
        keyStr = hex_to_string(key)
        keyData = {"key": f"{keyStr}"}
        json.dump(keyData, f)


@gestion_erreur_decorator
def encrypt_AES_GCM(msg: str | bytes, secretKey: str | bytes) -> tuple[str, str, str]:
    """
    Chiffre un message en utilisant AES en mode GCM.

    Args:
        msg (str | bytes): Le message à chiffrer.
        secretKey (str | bytes): La clé secrète pour le chiffrement.

    Returns:
        tuple[str, str, str]: Le message chiffré, le nonce et le tag d'authentification en hexadécimal.
    """
    if isinstance(secretKey,str):
        secretKey = string_to_hex(secretKey)
    if isinstance(msg, str):
        msg = msg.encode('utf-8')
    aesCipher = AES.new(secretKey, AES.MODE_GCM)
    ciphertext, authTag = aesCipher.encrypt_and_digest(msg)
    encryptedMsg = ciphertext, aesCipher.nonce, authTag
    return msg_decode(encryptedMsg)

@gestion_erreur_decorator
def msg_decode(encryptedMsg: tuple[bytes, bytes | bytearray | memoryview, bytes]) -> tuple[str, str, str]:
    """
    Convertit un message chiffré en format hexadécimal.

    Args:
        encryptedMsg (tuple[bytes, bytes | bytearray | memoryview, bytes]): Le message chiffré à convertir.

    Returns:
        tuple[str, str, str]: Le message chiffré, le nonce et le tag d'authentification en hexadécimal.
    """
    encryptedMsg = (
        binascii.hexlify(encryptedMsg[0]).decode('utf-8'), binascii.hexlify(encryptedMsg[1]).decode('utf-8'),
        binascii.hexlify(encryptedMsg[2]).decode('utf-8')
    )
    return encryptedMsg

@gestion_erreur_decorator
def msg_encode(encryptedMsg: tuple[str, str, str]) -> tuple[bytes, bytes, bytes]:
    """
    Convertit un message chiffré en hexadécimal en bytes.

    Args:
        encryptedMsg (tuple[str, str, str]): Le message chiffré en hexadécimal à convertir.

    Returns:
        tuple[bytes, bytes, bytes]: Le message chiffré, le nonce et le tag d'authentification en bytes.
    """
    encryptedMsg = (
        binascii.unhexlify(encryptedMsg[0]), binascii.unhexlify(encryptedMsg[1]), binascii.unhexlify(encryptedMsg[2])
    )
    return encryptedMsg

@gestion_erreur_decorator
def save_encrypt_message(encryptedMsg: tuple[str, str, str], path: str) -> None:
    """
    Sauvegarde un message chiffré dans un fichier JSON.

    Args:
        encryptedMsg (tuple[str, str, str]): Le message chiffré à sauvegarder.
        path (str): Le chemin du fichier de sauvegarde.
    """
    encryptedData = {'encryptMsg': {
        'ciphertext': encryptedMsg[0],
        'aesIV': encryptedMsg[1],
        'authTag': encryptedMsg[2]
    }}
    with open(path, "w") as f:
        json.dump(encryptedData, f)

@gestion_erreur_decorator
def string_to_hex(valueString: str) -> bytes:
    """
    Convertit une chaîne hexadécimale en bytes.

    Args:
        valueString (str): La chaîne hexadécimale à convertir.

    Returns:
        bytes: Les bytes correspondant à la chaîne hexadécimale.
    """
    valueBytes: bytes = bytes.fromhex(valueString)
    return valueBytes

@gestion_erreur_decorator
def read_file(path: str) -> tuple[Any, Any, Any]:
    """
    Lit un message chiffré depuis un fichier JSON.

    Args:
        path (str): Le chemin du fichier à lire.

    Returns:
        tuple[Any, Any, Any]: Le message chiffré, le nonce et le tag d'authentification en hexadécimal.
    """
    with open(path, "r") as file:
        encryptMsg = json.load(file)["encryptMsg"]
        encryptMsg = encryptMsg["ciphertext"], encryptMsg["aesIV"], encryptMsg["authTag"]
        return encryptMsg

@gestion_erreur_decorator
def decrypt_AES_GCM(encryptedMsg: [str, str, str], secretKey: str | bytes) -> str:
    """
    Déchiffre un message chiffré en utilisant AES en mode GCM.

    Args:
        encryptedMsg (tuple[str, str, str]): Le message chiffré à déchiffrer.
        secretKey (str | bytes): La clé secrète pour le déchiffrement.

    Returns:
        str: Le message déchiffré.
    """
    if isinstance(secretKey, str):
        secretKey: bytes = string_to_hex(secretKey)
    encryptedMsg: tuple[bytes, bytes, bytes] = msg_encode(encryptedMsg)
    ciphertext: bytes = encryptedMsg[0]
    nonce: bytes = encryptedMsg[1]
    authTag: bytes = encryptedMsg[2]

    aesCipher = AES.new(secretKey, AES.MODE_GCM, nonce)
    plaintext = aesCipher.decrypt_and_verify(ciphertext, authTag)
    return plaintext.decode('utf-8')
