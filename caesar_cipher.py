# Project 1: Encryption & Decryption with Visualization
from cryptography.fernet import Fernet
import matplotlib.pyplot as plt

class CaesarCipher:
    def __init__(self, shift: int):
        self.shift = shift

    def encrypt(self, text: str) -> str:
        result = ""
        for char in text:
            if char.isalpha():
                shift_base = ord('A') if char.isupper() else ord('a')
                result += chr((ord(char) - shift_base + self.shift) % 26 + shift_base)
            else:
                result += char
        return result

    def decrypt(self, text: str) -> str:
        result = ""
        for char in text:
            if char.isalpha():
                shift_base = ord('A') if char.isupper() else ord('a')
                result += chr((ord(char) - shift_base - self.shift) % 26 + shift_base)
            else:
                result += char
        return result

class AESCipher:
    def __init__(self, key: bytes = None):
        self.key = key or Fernet.generate_key()
        self.cipher = Fernet(self.key)

    def encrypt(self, text: str) -> bytes:
        return self.cipher.encrypt(text.encode())

    def decrypt(self, encrypted_text: bytes) -> str:
        return self.cipher.decrypt(encrypted_text).decode()

def visualize_caesar(original, encrypted):
    original_chars = list(original)
    encrypted_chars = list(encrypted)
    ascii_original = [ord(c) for c in original_chars]
    ascii_encrypted = [ord(c) for c in encrypted_chars]

    plt.figure(figsize=(10,5))
    plt.bar(original_chars, ascii_original, color='blue', alpha=0.6, label='Original ASCII')
    plt.bar(original_chars, ascii_encrypted, color='red', alpha=0.6, label='Encrypted ASCII')
    plt.xlabel("Characters")
    plt.ylabel("ASCII Value")
    plt.title("Caesar Cipher Encryption Visualization")
    plt.legend()
    plt.show()

def visualize_aes(original, encrypted):
    lengths = [len(original), len(encrypted)]
    labels = ['Original', 'AES Encrypted']
    colors = ['green', 'purple']

    plt.figure(figsize=(6,4))
    plt.bar(labels, lengths, color=colors)
    plt.ylabel("Number of Characters / Bytes")
    plt.title("AES Encryption: Message Length Comparison")
    plt.show()

def main():
    print("=== Caesar Cipher Demo ===")
    caesar = CaesarCipher(shift=3)
    text = "HelloWorld"
    encrypted_caesar = caesar.encrypt(text)
    decrypted_caesar = caesar.decrypt(encrypted_caesar)
    print(f"Original:  {text}")
    print(f"Encrypted: {encrypted_caesar}")
    print(f"Decrypted: {decrypted_caesar}")

    visualize_caesar(text, encrypted_caesar)

    print("\n=== AES Encryption Demo ===")
    aes = AESCipher()
    text2 = "Cybersecurity with Python"
    encrypted_aes = aes.encrypt(text2)
    decrypted_aes = aes.decrypt(encrypted_aes)
    print(f"Original:  {text2}")
    print(f"Encrypted: {encrypted_aes}")
    print(f"Decrypted: {decrypted_aes}")

    visualize_aes(text2, encrypted_aes)

    print("\nAES Key (save this!):", aes.key.decode())

if __name__ == "__main__":
    main()
