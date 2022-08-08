#!/usr/bin/env python3
# -*- coding: utf_8 -*-

import time
import json
import base64
import socket
import x25519
import hashlib
import secrets
import binascii
from urllib.request import urlopen
from nacl.signing import SigningKey, VerifyKey # pip3 install pynacl
from Crypto.Cipher import AES # pip3 install pycrypto
from Crypto.Util import Counter


class Adnl():
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
	#end define
	
	def AddLog(self, text, type):
		if self.local:
			self.local.AddLog(text, type)
		else:
			print(text)
	#end define

	def Connect(self, host, port, pubkeyB64):
		handshake = self.CreateHandshake(pubkeyB64)

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

	def CreateHandshake(self, pubkeyB64):
		other_pub = base64.b64decode(pubkeyB64) # 32 bytes, ed25519
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
	
	def CRC32(self, text):
		buff = binascii.crc32(text.encode('utf8'))
		result = int.to_bytes(buff, length=4, byteorder="little")
		return result
	#end define
	
	def AlignBytes(self, data, alen=8):
		dlen = len(data)
		nlen = 0
		if dlen % alen != 0:
			nlen = alen - dlen % alen
		buff = bytes.fromhex("00")
		result = data + buff * nlen
		return result
	#end define
	
	def TlLen(self, data):
		dlen = len(data)
		if dlen < 254:
			dlen = dlen.to_bytes(1, byteorder="little")
		else:
			buff = bytes.fromhex("fe")
			dlen = buff + dlen.to_bytes(3, byteorder="little")
		return dlen
	#end define
	
	def GetTl(self, data):
		if data[0] == bytes.fromhex("fe"):
			buff = data[1:4]
		else:
			buff = data[0:1]
		dlen = int.from_bytes(buff, byteorder="little")
		start = len(buff)
		end = start + dlen
		rdata = data[start:end]
		return rdata
	#end define
	
	def Int(self, data):
		return int.from_bytes(data, byteorder="little", signed=True)
	#end define
	
	def Ping(self):
		# send
		scheme_sid = self.CRC32("tcp.ping random_id:long = tcp.Pong")
		random_sid = secrets.token_bytes(8)
		sdata = scheme_sid + random_sid
		self.SendDatagram(sdata)
		
		# get
		rdata = self.GetDatagram()
		scheme_rid = self.CRC32("tcp.pong random_id:long = tcp.Pong")
		if rdata[0:4] != scheme_rid:
			raise Exception("Adnl ping error: scheme_rid != tcp.pong")
		if rdata[4:] != random_sid:
			raise Exception("Adnl ping error: random_rid != random_sid")
		self.AddLog("ping - ok", "debug")
	#end define
	
	def Query(self, data):
		# send
		scheme_sid = self.CRC32("adnl.message.query query_id:int256 query:bytes = adnl.Message")
		query_id = secrets.token_bytes(32)
		dlen = self.TlLen(data)
		data = self.AlignBytes(dlen + data, 16)
		sdata = scheme_sid + query_id + data
		self.SendDatagram(sdata)
		
		# get
		rdata = self.GetDatagram()
		print("Query rdata:", rdata.hex())
		scheme_rid = self.CRC32("adnl.message.answer query_id:int256 answer:bytes = adnl.Message")
		if rdata[0:4] != scheme_rid:
			raise Exception("Adnl query error: scheme_rid != adnl.message.answer")
		if rdata[4:36] != query_id:
			raise Exception("Adnl query error: query_sid != query_rid")
		result = rdata[36:]
		return result
	#end define
	
	def LiteServerQuery(self, data):
		# send
		scheme_sid = self.CRC32("liteServer.query data:bytes = Object")
		dlen = self.TlLen(data)
		data = self.AlignBytes(dlen + data, 8)
		sdata = scheme_sid + data
		
		# get
		rdata = self.Query(sdata)
		rdata = self.GetTl(rdata)
		return rdata
	#end define
	
	def GetMasterchainInfo(self):
		# send
		scheme_sid = self.CRC32("liteServer.getMasterchainInfo = liteServer.MasterchainInfo")
		
		# get
		rdata = self.LiteServerQuery(scheme_sid)
		scheme_rid = self.CRC32("liteServer.masterchainInfo last:tonNode.blockIdExt state_root_hash:int256 init:tonNode.zeroStateIdExt = liteServer.MasterchainInfo")
		if rdata[0:4] != scheme_rid:
			raise Exception("GetMasterchainInfo error: scheme_rid != liteServer.masterchainInfo.answer")
		data = rdata[4:]
		result = dict()
		last = dict()
		last["workchain"] = self.Int(data[0:4]) # 4 bytes
		#last["shard"] = self.Int(data[4:12])
		last["shard"] = data[4:12].hex()  # 4 bytes
		last["seqno"] = self.Int(data[12:16]) # 4 bytes
		last["root_hash"] = data[16:48].hex() # 32 bytes
		last["file_hash"] = data[48:80].hex() # 32 bytes
		result["last"] = last
		result["state_root_hash"] = data[80:112].hex() # 32 bytes
		init = dict()
		init["workchain"] = self.Int(data[112:116]) # 4 bytes
		init["root_hash"] = data[116:148].hex() # 32 bytes
		init["file_hash"] = data[148:180].hex() # 32 bytes
		result["init"] = init
		return result
#end class



host = "5.9.10.47"
port = 19949
pubkeyB64 = "n4VDnSCUuSpjnCyUk9e3QOOd6o0ItSWYbTnW3Wnn8wk="

adnl = Adnl()
adnl.Connect(host, port, pubkeyB64)

for i in range(3):
	time.sleep(1)
	adnl.Ping()
#end for

data = adnl.GetMasterchainInfo()
print("GetMasterchainInfo:")
print(json.dumps(data, indent=4))
