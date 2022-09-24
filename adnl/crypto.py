import binascii
import hashlib
import secrets

from Crypto.Cipher import AES
from Crypto.Util import Counter
from nacl.signing import SigningKey, VerifyKey
import x25519


def create_aes_cipher(key, nonce):
    ctr_init_value = int.from_bytes(nonce, "big")
    ctr = Counter.new(128, initial_value=ctr_init_value)
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
    return cipher


def sha256(data):
    return hashlib.sha256(data).digest()


def crc32(text):
    buff = binascii.crc32(text.encode('utf8'))
    return int.to_bytes(buff, length=4, byteorder="little")


def aes_encrypt_with_secret(aes_params, secret):
    hash_ = sha256(aes_params)
    key = secret[0:16] + hash_[16:32]
    nonce = hash_[0:4] + secret[20:32]
    cipher = create_aes_cipher(key, nonce)
    return cipher.encrypt(aes_params)


def generate_secret_key(other_pub, private_key):
    peer_vk = VerifyKey(other_pub)  # 32 bytes
    peer_public_key = peer_vk.to_curve25519_public_key().encode()  # x25519
    return x25519.scalar_mult(private_key, peer_public_key)  # x25519


def generate_local_keys():
    """
    :return: (LocalPrivateKey, LocalPublicKey, PrivateKey)
    :type: Tuple
    """
    sk = SigningKey.generate()  # 32 bytes
    local_private = sk.encode()  # ed25519
    local_pub = sk.verify_key.encode()  # ed25519
    private_key = sk.to_curve25519_private_key().encode()  # x25519
    return local_private, local_pub, private_key


def nonce() -> bytes:
    """
    :return: Random 32 bytes
    """
    return secrets.token_bytes(32)


def random_bytes(n) -> bytes:
    return secrets.token_bytes(n)
