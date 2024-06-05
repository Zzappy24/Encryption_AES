from function import generate_AES_Key, string_to_hex, hex_to_string, save_key

if __name__ == "__main__":
    newKey = generate_AES_Key()
    save_key(newKey, "./keyGenerated/key.txt")
    print(hex_to_string(newKey))
