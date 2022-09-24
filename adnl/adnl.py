import base64
import secrets
import socket

from . import crypto
from . import query
from . import tl_object
from .tl_object import models
from . import const


class Adnl:
    def __init__(self, host=None, port=None, pub_key=None):
        self.local = None
        self.sock: socket = None
        self.local_private = None
        self.rx_key = None
        self.tx_key = None
        self.rx_nonce = None
        self.tx_nonce = None
        self.rx_cipher = None
        self.tx_cipher = None
        self.host = host
        self.port = port
        self.pub_key = pub_key

    def add_log(self, text, type_):
        if self.local:
            self.local.add_log(text, type_)
        else:
            print(text)

    def connect(self, host, port, pubkey_b64):
        handshake = self.create_handshake(pubkey_b64)
        # create rx, tx cipher
        self.rx_cipher = crypto.create_aes_cipher(self.rx_key, self.rx_nonce)
        self.tx_cipher = crypto.create_aes_cipher(self.tx_key, self.tx_nonce)
        # send handshake
        self.sock = socket.socket()
        self.sock.settimeout(3)
        self.sock.connect((host, port))
        self.sock.send(handshake)
        self.get_datagram()

    def create_handshake(self, pubkey_b64):
        other_pub = base64.b64decode(pubkey_b64)  # 32 bytes, ed25519
        other_id = self.get_id(other_pub)  # 32 bytes

        # create local private key
        self.local_private, local_pub, private_key = (
            crypto.generate_local_keys()
        )

        # create secret key
        secret = crypto.generate_secret_key(other_pub, private_key)

        # create aes_params
        self.rx_key = secrets.token_bytes(32)  # 32 bytes
        self.tx_key = secrets.token_bytes(32)  # 32 bytes
        self.rx_nonce = secrets.token_bytes(16)  # 16 bytes
        self.tx_nonce = secrets.token_bytes(16)  # 16 bytes
        padding = secrets.token_bytes(64)  # 64 bytes
        # 160 bytes
        aes_params = (
                self.rx_key + self.tx_key +
                self.rx_nonce + self.tx_nonce + padding
        )
        # create handshake
        checksum = crypto.sha256(aes_params)  # 32 bytes
        encrypted_aes_params = (
            crypto.aes_encrypt_with_secret(aes_params, secret)
        )
        # 256 bytes
        handshake = other_id + local_pub + checksum + encrypted_aes_params
        return handshake

    def get_datagram(self):
        data = self.receive(4)
        dlen = int.from_bytes(data, "little")
        data = self.receive(dlen)
        nonce = data[0:32]
        buffer = data[32:-32]
        checksum = data[-32:]
        hash = crypto.sha256(nonce + buffer)
        if hash != checksum:
            print("buffer:", buffer.hex())
            print("hash:", hash.hex())
            print("checksum:", checksum.hex())
            raise Exception("get_datagram error: Checksum does not match")
        return buffer

    def send_datagram(self, data):
        nonce = secrets.token_bytes(32)
        checksum = crypto.sha256(nonce + data)
        dlen = len(nonce + data + checksum)
        dlen = dlen.to_bytes(4, byteorder="little")
        sdata = dlen + nonce + data + checksum
        self.send(sdata)

    def send(self, data):
        sdata = self.tx_cipher.encrypt(data)
        self.sock.send(sdata)

    def receive(self, dlen):
        rdata = self.sock.recv(dlen)
        if len(rdata) == 0:
            raise Exception("receive error: no data")
        result = self.rx_cipher.decrypt(rdata)
        return result

    def get_id(self, pubkey):
        magic = bytes.fromhex("c6b41348")  # 0x4813b4c6
        result = crypto.sha256(magic + pubkey)
        return result

    @staticmethod
    def align_bytes(data, alen=8):
        dlen = len(data)
        nlen = 0
        if dlen % alen != 0:
            nlen = alen - dlen % alen
        buff = bytes.fromhex("00")
        result = data + buff * nlen
        return result

    @staticmethod
    def tl_len(data):
        dlen = len(data)
        if dlen < 254:
            dlen = dlen.to_bytes(1, byteorder="little")
        else:
            buff = bytes.fromhex("fe")
            dlen = buff + dlen.to_bytes(3, byteorder="little")
        return dlen

    @staticmethod
    def fetch_int(data):
        return int.from_bytes(data, byteorder="little", signed=True)

    def ping(self):
        # send
        q = query.PingQuery()
        self.send(q.build())

        # get
        rdata = self.get_datagram()
        q.validate_response(rdata)
        self.add_log("ping - ok", "debug")

    def make_query(self, adnl_query: query.AdnlMsgQuery):
        # send
        self.send(adnl_query.build())

        # get
        rdata = self.get_datagram()
        print("Query rdata:", rdata.hex())
        adnl_query.check_response(rdata, exception=True)
        result = rdata[36:]
        return result

    def get_masterchain_info(self):
        ms_model = models.MasterchainInfo()
        adnl_query = query.schema_query(const.SCHEMA_GET_MASTERCHAIN)
        rdata = self.make_query(adnl_query)
        tl_bytes = tl_object.TLBytes(rdata, packed=True)
        rdata = tl_bytes.get_bytes()

        if not ms_model.validate_response(rdata):
            raise Exception("GetMasterchainInfo error")

        return ms_model.unpack(rdata)

    def __enter__(self):
        self.connect(self.host, self.port, self.pub_key)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.sock.shutdown(socket.SHUT_RDWR)
