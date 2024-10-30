from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import PKCS1_OAEP
import base64

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


from User import *
from converter import public_key_wind_to_pem, private_key_wind_to_pem


def bytes_to_public_key(public_key_bytes):
    # Generate RSA key pair (128-byte size)
    rsa_key = RSA.generate(1024)  # 1024 bits = 128 bytes for the private key
    private_key = rsa_key.export_key()
    public_key = rsa_key.publickey().export_key()

    public_key_bytes = rsa_key.export_key(format='DER')

    print("RSA Public Key (Base64):")
    print(base64.b64encode(public_key).decode())

    # Generate AES symmetric key (32 bytes)
    aes_key = get_random_bytes(32)  # 32 bytes = 256 bits for AES

    # Initialize AES cipher in CBC mode
    # AES requires an initialization vector (IV) for CBC mode, we'll generate one
    iv = get_random_bytes(AES.block_size)  # AES block size is 16 bytes

    # Create AES cipher
    aes_cipher = AES.new(aes_key, AES.MODE_CBC, iv)

    # Ensure the RSA public key is padded to match AES block size (16 bytes)
    # PKCS7 padding to make sure it's a multiple of the AES block size (16 bytes)
    pad_length = AES.block_size - len(public_key) % AES.block_size
    public_key_padded = public_key + bytes([pad_length]) * pad_length

    # Encrypt RSA public key using AES in CBC mode
    encrypted_public_key = aes_cipher.encrypt(public_key_padded)

    # Output encrypted public key (Base64 encoded)
    print("\nEncrypted RSA Public Key (Base64):")
    print(base64.b64encode(encrypted_public_key).decode())

    # To verify decryption, let's create the AES cipher again with the same key and IV
    aes_cipher_decrypt = AES.new(aes_key, AES.MODE_CBC, iv)

    # Decrypt the public key and remove padding
    decrypted_public_key_padded = aes_cipher_decrypt.decrypt(encrypted_public_key)
    pad_length = decrypted_public_key_padded[-1]
    decrypted_public_key = decrypted_public_key_padded[:-pad_length]

    print("\nDecrypted RSA Public Key (Base64):")
    print(base64.b64encode(decrypted_public_key).decode())



def encrypt_rsa(pub_key_bytes, data):
    public_key = RSA.import_key(pub_key_bytes)
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_data = cipher_rsa.encrypt(data)

    # encrypted_data = data #@@@@@@@@@@@@@@@@

    return encrypted_data


def decrypt_rsa(priv_key_bytes, encrypted_data):
    privet_key = RSA.import_key(priv_key_bytes)
    cipher_rsa = PKCS1_OAEP.new(privet_key)
    decrypted_data = cipher_rsa.decrypt(encrypted_data)
    return decrypted_data


def check():
    rsa = RSA.generate(1024)
    pub_key = rsa.public_key().export_key(format='DER')
    priv_key = rsa.export_key("DER")

    print(pub_key)
    print('\n\n\n')
    print(priv_key)
    exit(0)

    data = b'stam data'

    usr = User(12121212, 'Ron')
    key = usr.generate_aes_key()
    print(key)


    encrypted_data = encrypt_rsa(pub_key, key)
    print(encrypted_data)

    decrypted_data = decrypt_rsa(priv_key, encrypted_data)
    print(decrypted_data)




import base64

def stam():

    data = b'Hello bro'

    public_key_base64 = """
    MIGdMA0GCSqGSIb3DQEBAQUAA4GLADCBhwKBgQDI8LRWiP/QEQul6O2RmRp0cq+zd9UEJeNz
UQZ80Fnm4YK4wIuTngMX50v+o81L0j7yAgqu1e9OgDO5IKrWJe6awCGMGnydPruUNyf0Jgnk
Um9jKUcnZU2tFT6cMpS39OheXJkN3bJEHTfHESxcd8lGAjCIznS3X4nh6dIMabx+0wIBEQ==
    """

    public_key_base64 = public_key_base64.replace("\n", "").replace("\r", "")

    # המרת המחרוזת ממחרוזת Base64 למערך של בתים
    public_key_bytes = base64.b64decode(public_key_base64)



    encrypted_data = encrypt_rsa(public_key_bytes, data)

    print(base64.b64encode(encrypted_data).decode('utf-8'))



    exit(0)

# stam()