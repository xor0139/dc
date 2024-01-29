from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
import argparse

parser = argparse.ArgumentParser(description="<<< BearCrypto >>> Криптор / декриптор файлов")
parser.add_argument("-c", help="Криптовать файл")
parser.add_argument("-d", help="Декриптовать файл")
parser.add_argument("-g", help="Генерировать ключи")

def generate_keys(folder):
    """Генерация приватного и публичного ключа"""
    key = RSA.generate(2048)
    private_key = key.export_key()
    with open(f"{folder}/privateKey.pem", "wb") as file:
        file.write(private_key)

    public_key = key.public_key().export_key()
    with open(f"{folder}/publicKey.pem", "wb") as file:
        file.write(public_key)

    print("Ключи сгенерированы!!!")

def encrypt(filename):
    """Шифрование, в аргументе передаем путь к файлу"""
    with open(filename, "rb") as file:
        data = file.read()

    recipient_key = RSA.import_key(open("publicKey.pem").read())
    session_key = get_random_bytes(16)

    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    enc_session_key = cipher_rsa.encrypt(session_key)

    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(data)

    with open(filename, "wb") as file:
        file.write(enc_session_key)
        file.write(cipher_aes.nonce)
        file.write(tag)
        file.write(ciphertext)

    print(f"Файл {filename} зашифрован!!!")

def decrypt(filename):
    """Дешифрование, в аргументе передаем путь к файлу"""
    private_key = RSA.import_key(open("privateKey.pem").read())

    with open(filename, "rb") as file:
        enc_session_key = file.read(private_key.size_in_bytes())
        nonce = file.read(16)
        tag = file.read(16)
        ciphertext = file.read()

    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(enc_session_key)

    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    data = cipher_aes.decrypt_and_verify(ciphertext, tag)

    with open(filename, "wb") as file:
        file.write(data)

    print(f"Файл {filename} расшифрован!!!")



if __name__ == "__main__":
    args = parser.parse_args()
    if args.g:
        generate_keys(args.g)
    elif args.c:
        encrypt(args.c)
    elif args.d:
        decrypt(args.d)