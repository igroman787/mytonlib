#!/usr/bin/env python3
# -*- coding: utf_8 -*-

import os
import time
import json
import base64
import socket
import x25519 # pip3 install x25519
import hashlib
import secrets
import binascii
import urllib.request
from nacl.signing import SigningKey, VerifyKey # pip3 install pynacl
from Crypto.Cipher import AES # pip3 install pycrypto
from Crypto.Util import Counter

from tl import TlSchemes, BytesSlicer, Int, TlLen
from utils import ParseAddr


class Adnl:
	def __init__(self):
		self.local = None
		self.sock = None
		self.local_priv = None
		self.rx_key = None
		self.tx_key = None
		self.rx_nonce = None
		self.tx_nonce = None
		self.rx_cipher = None
		self.tx_cipher = None
		self.schemes = TlSchemes()
		self.LoadSchemes()
	#end define
	
	def LoadSchemes(self):
		dir = "/usr/src/ton/tl/generate/scheme/"
		if os.path.isdir(dir):
			self.schemes.LoadSchemes(dir)
		else:
			raise Exception("TL schemes not found. Use command: `cd /usr/src && git clone https://github.com/ton-blockchain/ton`")
	#end define
	
	def AddLog(self, text, type):
		if self.local:
			self.local.AddLog(text, type)
		else:
			print(text)
	#end define

	def Connect(self, host, port, pubkey):
		handshake = self.CreateHandshake(pubkey)

		# create rx, tx cipher
		self.rx_cipher = self.CreateAesCipher(self.rx_key, self.rx_nonce)
		self.tx_cipher = self.CreateAesCipher(self.tx_key, self.tx_nonce)

		# send handshake
		self.sock = socket.socket()
		self.sock.settimeout(3)
		self.sock.connect((host, port))
		self.sock.send(handshake)

		self.GetDatagram()
	#end define

	def CreateHandshake(self, pubkey):
		other_pub = base64.b64decode(pubkey) # 32 bytes, ed25519
		other_id = self.GetId(other_pub) # 32 bytes

		# create local private key
		sk = SigningKey.generate() # 32 bytes
		self.local_priv = sk.encode() # ed25519
		local_pub = sk.verify_key.encode() # ed25519
		private_key = sk.to_curve25519_private_key().encode() # x25519

		# create secret key
		peer_vk = VerifyKey(other_pub) # 32 bytes
		peer_public_key = peer_vk.to_curve25519_public_key().encode() # x25519
		secret = x25519.scalar_mult(private_key, peer_public_key) # x25519

		# create aes_params
		self.rx_key = secrets.token_bytes(32) # 32 bytes
		self.tx_key = secrets.token_bytes(32) # 32 bytes
		self.rx_nonce = secrets.token_bytes(16) # 16 bytes
		self.tx_nonce = secrets.token_bytes(16) # 16 bytes
		padding = secrets.token_bytes(64) # 64 bytes
		aes_params = self.rx_key + self.tx_key + self.rx_nonce + self.tx_nonce + padding # 160 bytes

		#create handshake
		checksum = self.SHA256(aes_params) # 32 bytes
		encrypted_aes_params = self.AesEncryptWithSecret(aes_params, secret)
		handshake = other_id + local_pub + checksum + encrypted_aes_params # 256 bytes
		return handshake
	#end define

	def GetDatagram(self):
		data = self.Receive(4)
		dlen = int.from_bytes(data, "little")
		data = self.Receive(dlen)
		nonce = data[0:32]
		buffer = data[32:-32]
		checksum = data[-32:]
		hash = self.SHA256(nonce + buffer)
		if hash != checksum:
			print("buffer:", buffer.hex())
			print("hash:", hash.hex())
			print("checksum:", checksum.hex())
			raise Exception("GetDatagram error: Checksum does not match")
		return buffer
	#end define

	def SendDatagram(self, data):
		nonce = secrets.token_bytes(32)
		checksum = self.SHA256(nonce + data)
		dlen = len(nonce + data + checksum)
		dlen = dlen.to_bytes(4, byteorder="little")
		sdata = dlen + nonce + data + checksum
		self.Send(sdata)
	#end define

	def Send(self, data):
		sdata = self.tx_cipher.encrypt(data)
		self.sock.send(sdata)
	#end define

	def Receive(self, dlen):
		rdata = self.sock.recv(dlen)
		if len(rdata) == 0:
			raise Exception("Receive error: no data")
		result = self.rx_cipher.decrypt(rdata)
		return result
	#end define

	def AesEncryptWithSecret(self, aes_params, secret):
		hash = self.SHA256(aes_params)
		key = secret[0:16] + hash[16:32]
		nonce = hash[0:4] + secret[20:32]
		cipher = self.CreateAesCipher(key, nonce)
		result = cipher.encrypt(aes_params)
		return result
	#end define

	def CreateAesCipher(self, key, nonce):
		ctrInitValue = int.from_bytes(nonce, "big")
		ctr = Counter.new(128, initial_value=ctrInitValue)
		cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
		return cipher
	#end define

	def SHA256(self, data):
		return hashlib.sha256(data).digest()
	#end define

	def GetId(self, pubkey):
		magic = bytes.fromhex("c6b41348") # 0x4813b4c6
		result = self.SHA256(magic + pubkey)
		return result
	#end define
	
	def AlignBytes(self, data, alen=4):
		dlen = len(data)
		nlen = 0
		if dlen % alen != 0:
			nlen = alen - dlen % alen
		buff = bytes.fromhex("00")
		result = data + buff * nlen
		return result
	#end define
	
	def Ping(self):
		# send
		send_scheme = self.schemes.GetSchemeByName("tcp.ping")
		random_id = secrets.token_bytes(8)
		send_data = send_scheme.id + random_id
		self.SendDatagram(send_data)
		
		# get
		read_data = self.GetDatagram()
		slicer = BytesSlicer(read_data)
		read_scheme_id = slicer(4)
		read_scheme = self.schemes.GetSchemeById(read_scheme_id)
		data = read_scheme.Deserialize(slicer)
		if data.random_id != Int(random_id):
			raise Exception("Adnl ping error: random_id does not match")
		self.AddLog("ping - ok", "debug")
	#end define
	
	def Query(self, data):
		# send
		send_scheme = self.schemes.GetSchemeByName("adnl.message.query")
		query_id = secrets.token_bytes(32)
		dlen = TlLen(data)
		data = self.AlignBytes(dlen + data)
		send_data = send_scheme.id + query_id + data
		self.SendDatagram(send_data)
		print(f"send_data: {send_data.hex()}")
		
		# get
		read_data = self.GetDatagram()
		print(f"read_data: {read_data.hex()}")
		slicer = BytesSlicer(read_data)
		read_scheme_id = slicer(4)
		read_scheme = self.schemes.GetSchemeById(read_scheme_id)
		data = read_scheme.Deserialize(slicer)
		if query_id.hex() != data.query_id:
			raise Exception("Adnl query error: query_id does not match")
		return data.answer
	#end define
	
	def LiteServerQuery(self, data):
		# send
		send_scheme = self.schemes.GetSchemeByName("liteServer.query")
		dlen = TlLen(data)
		data = self.AlignBytes(dlen + data)
		send_data = send_scheme.id + data
		
		# get
		read_data = self.Query(send_data)
		return read_data
	#end define
	
	def Get(self, function_name, **data):
		# send
		send_scheme = self.schemes.GetSchemeByName(f"liteServer.{function_name}")
		send_data = send_scheme.id + send_scheme.Serialize(**data)
		
		# get
		read_data = self.LiteServerQuery(send_data)
		slicer = BytesSlicer(read_data)
		read_scheme_id = slicer(4)
		read_scheme = self.schemes.GetSchemeById(read_scheme_id)
		print(f"scheme_id: {read_scheme_id.hex()}")
		print(f"scheme: {read_scheme.name}")
		result = read_scheme.Deserialize(slicer)
		return result
	#end define
	
	def GetMasterchainInfo(self):
		return self.Get("getMasterchainInfo")
	#end define
	
	def GetTime(self):
		return self.Get("getTime")
	#end define
	
	def GetAccountState(self, input_addr):
		data = self.Get("getMasterchainInfo")
		workchain, addr = ParseAddr(input_addr)
		account = {"workchain":workchain, "id":addr}
		return self.Get("getAccountState", id=data.last, account=account)
	#end define
#end class



host = "5.9.10.47"
port = 19949
pubkey = "n4VDnSCUuSpjnCyUk9e3QOOd6o0ItSWYbTnW3Wnn8wk="

adnl = Adnl()
adnl.Connect(host, port, pubkey)

for i in range(3):
	time.sleep(1)
	adnl.Ping()
#end for

data = adnl.GetMasterchainInfo()
print("GetMasterchainInfo:")
print(json.dumps(data, indent=4))
print(data.last.seqno)

data = adnl.GetTime()
print("GetTime:")
print(json.dumps(data, indent=4))

data = adnl.GetAccountState("EQCD39VS5jcptHL8vMjEXrzGaRcCVYto7HUn4bpAOg8xqB2N")
print(f"GetAccountState: {data}")
print(f"state: {data.state.hex()}")
#print(json.dumps(data, indent=4))


