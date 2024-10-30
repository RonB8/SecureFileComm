import struct
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


def public_key_blob_to_der(blob):
    # unpack the header (first 20 bytes)
    header = blob[:20]

    # Extract modulus length
    mod_length = struct.unpack('I', header[16:20])[0]

    # Extract exponent length and value
    exponent_length = struct.unpack('H', header[20:22])[0]
    exponent = blob[22:22 + exponent_length]

    # Extract modulus
    modulus = blob[22 + exponent_length:22 + exponent_length + mod_length]

    # Create RSA public key
    public_key = rsa.RSAPublicNumbers(
        e=int.from_bytes(exponent, byteorder='big'),
        n=int.from_bytes(modulus, byteorder='big')
    ).public_key()

    # Serialize the public key in DER format
    der_key = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return der_key




def public_key_wind_to_pem(pub_key):
    res = pub_key

    befpemwind = b'-----BEGIN PUBLIC KEY-----BgIAAACkAABSU0ExAAQAAAEAAQ'
    aftpemwind = b'== -----END PUBLIC KEY-----'

    befpem = b'-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQ'
    aftpem = b'IDAQAB\n-----END PUBLIC KEY-----'

    if res.startswith(befpemwind):
        res = res.replace(befpemwind, befpem, 1)

    # if pub_key.endswith(aftpemwind):
        res = res[:-len(aftpemwind)] + aftpem

    return res



def private_key_wind_to_pem(priv_key):
    res = priv_key

    befpemprivwind = b'-----BEGIN PRIVATE KEY-----BwIAAACkAABSU0EyAAQAAAEAAQ'
    aftpemprivwind = b'= -----END PRIVATE KEY-----'

    befpempriv = b'-----BEGIN RSA PRIVATE KEY-----\nMIICXAIBAAKBgQC'
    aftpempriv = b'=\n-----END RSA PRIVATE KEY-----'

    if res.startswith(befpemprivwind):
        res = res.replace(befpemprivwind, befpempriv, 1)

    # if priv_key.endswith(aftpemprivwind):
        res = res[:-len(aftpemprivwind)] + aftpempriv

    return res