from cryptography.fernet import Fernet


def caesar_encrypt(text, shift):
    result = ""
    for char in text:
        if char.isalpha(): 
            shift_base = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - shift_base + shift) % 26 + shift_base)
        else:
            result += char
    return result

def caesar_decrypt(text, shift):
    return caesar_encrypt(text, -shift)


key = Fernet.generate_key() 
cipher = Fernet(key)
print("AES Encryption Key (save this!):", key.decode())

message = input("Enter the message to encrypt: ")
shift = int(input("Enter Caesar Cipher shift number: "))


caesar_encrypted = caesar_encrypt(message, shift)
print("\nStep 1 - Caesar Encrypted:", caesar_encrypted)

aes_encrypted = cipher.encrypt(caesar_encrypted.encode())
print("Step 2 - AES Encrypted:", aes_encrypted.decode())


aes_decrypted = cipher.decrypt(aes_encrypted).decode()
print("Step 3 - AES Decrypted:", aes_decrypted)

final_decrypted = caesar_decrypt(aes_decrypted, shift)
print("Step 4 - Final Decrypted Message:", final_decrypted)
