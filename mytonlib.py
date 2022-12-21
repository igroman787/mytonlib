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
import fastcrc # pip3 install fastcrc
import urllib.request
from io import BytesIO as ByteStream
from bitstring import BitArray
from nacl.signing import SigningKey, VerifyKey # pip3 install pynacl
from Crypto.Cipher import AES # pip3 install pycrypto
from Crypto.Util import Counter

from tl import TlSchemes, Int, tl_len
from tlb import TlbSchemes
from boc import serialize_boc, deserialize_boc
from utils import ParseAddr
from mytypes import cell2dict


def tup(**data):
	return data
#end define

class AdnlUdpClient():
	def __init__(self):
		self.local = None
		self.sock = None
		self.local_private_key = secrets.token_bytes(32)
		self.channel_private_key = secrets.token_bytes(32)
		self.tl_schemes = TlSchemes()
		self.tlb_schemes = TlbSchemes()
		self.load_tl_schemes()
		self.load_tlb_schemes()
	#end define
	
	def load_tl_schemes(self):
		dir = "/usr/src/ton/tl/generate/scheme/"
		if os.path.isdir(dir):
			self.tl_schemes.load_schemes(dir)
		else:
			raise Exception("Tl schemes not found. Use command: `cd /usr/src && git clone https://github.com/ton-blockchain/ton`")
	#end define
	
	def load_tlb_schemes(self):
		dir = "/usr/src/ton/crypto/block/"
		if os.path.isdir(dir):
			self.tlb_schemes.load_schemes(dir)
		else:
			raise Exception("Tlb schemes not found. Use command: `cd /usr/src && git clone https://github.com/ton-blockchain/ton`")
	#end define
	
	def set_flags(self, flags):
		sep = ' '
		mode_len = 32
		mode_bin = BitArray(mode_len)
		flags = flags.replace('.', sep)
		flags = flags.replace(',', sep)
		flags = flags.split(sep)
		for item in flags:
			if item.isdigit():
				index = mode_len - int(item) - 1
				mode_bin[index] = True
		#end for
		
		return mode_bin.uint
	#end define
	
	def connect(self, host, port, peer_public_key_b64):
		timestamp = int(time.time())
		peer_public_key = base64.b64decode(peer_public_key_b64)
		peer_id = self.get_id(peer_public_key)
		
		local_public_key = self.get_public_key(self.local_private_key)
		channel_public_key = self.get_public_key(self.channel_private_key)
		local_id = self.get_id(local_public_key)
		#print(f"peer_public_key: {peer_public_key.hex()}")
		#print(f"peer_id: {peer_id.hex()}")
		#print(f"local_public_key: {local_public_key.hex()}")
		#print(f"channel_public_key: {channel_public_key.hex()}")
		
		# create Channel message
		#scheme = self.tl_schemes.get_scheme_by_name("adnl.message.createChannel")
		#create_channel_message = scheme.id + scheme.serialize(key=channel_local_pub.hex(), date=timestamp)
		
		# create PublicKey message
		#scheme = self.tl_schemes.get_scheme_by_name("pub.ed25519")
		#public_key_message = scheme.id + scheme.serialize(key=local_pub.hex())
		
		# create 
		query_id = secrets.token_bytes(32).hex() # 32 bytes
		#print(f"query_id: {query_id}")
		scheme = self.tl_schemes.get_scheme_by_name("dht.getSignedAddressList")
		query = scheme.id
		
		# create AddressList message
		#scheme = self.tl_schemes.get_scheme_by_name("adnl.addressList")
		#address_list_message = scheme.serialize(
		#	addrs=[], version=timestamp, reinit_date=timestamp, priority=0, expire_at=0)
		
		# create PacketContents message
		rand1 = secrets.token_bytes(15) # 15 bytes
		rand2 = secrets.token_bytes(15) # 15 bytes
		#print(f"rand1: {rand1.hex()}")
		#print(f"rand2: {rand2.hex()}")
		scheme = self.tl_schemes.get_scheme_by_name("adnl.packetContents")
		packet_contents_message = scheme.id + scheme.serialize(
			rand1 = rand1,
			flags = self.set_flags("flags.0,3,4,6,7,8,10"),
			#_from = public_key_message,
			_from = tup(scheme_name="pub.ed25519", key=local_public_key.hex()),
			#from_short = 
			#message = create_channel_message,
			#message = tup(scheme_name="adnl.message.createChannel", key=channel_public_key.hex(), date=timestamp),
			messages = [
							tup(scheme_name="adnl.message.createChannel", key=channel_public_key.hex(), date=timestamp),
							tup(scheme_name="adnl.message.query", query_id=query_id, query=query)
						],
			#address = address_list_message,
			address = tup(scheme_name="adnl.addressList", addrs=[], version=timestamp, reinit_date=timestamp, priority=0, expire_at=0),
			#priority_address = 
			seqno = 1,
			confirm_seqno = 0,
			recv_addr_list_version = timestamp,
			#recv_priority_addr_list_version = 
			reinit_date = timestamp,
			dst_reinit_date = 0,
			#signature = 
			rand2 = rand2
		)
		#print(f"packet_contents_message: {packet_contents_message.hex()}")
		
		signed_message = self.sign_message(self.local_private_key, packet_contents_message)
		#print(f"signed_message: {signed_message.hex()}")
		packet_contents_message = scheme.id + scheme.serialize(
			rand1 = rand1,
			flags = self.set_flags("flags.0,3,4,6,7,8,10,11"),
			#_from = public_key_message,
			_from = tup(scheme_name="pub.ed25519", key=local_public_key.hex()),
			#from_short = 
			#message = create_channel_message,
			#message = tup(scheme_name="adnl.message.createChannel", key=channel_public_key.hex(), date=timestamp),
			messages = [
							tup(scheme_name="adnl.message.createChannel", key=channel_public_key.hex(), date=timestamp),
							tup(scheme_name="adnl.message.query", query_id=query_id, query=query)
						],
			#address = address_list_message,
			address = tup(scheme_name="adnl.addressList", addrs=[], version=timestamp, reinit_date=timestamp, priority=0, expire_at=0),
			#priority_address = 
			seqno = 1,
			confirm_seqno = 0,
			recv_addr_list_version = timestamp,
			#recv_priority_addr_list_version = 
			reinit_date = timestamp,
			dst_reinit_date = 0,
			signature = signed_message,
			rand2 = rand2
		)
		#print(f"packet_contents_message: {packet_contents_message.hex()}")
		
		checksum = self.sha256(packet_contents_message)
		secret = self.get_secret(self.local_private_key, peer_public_key)
		encrypted_message = self.aes_encrypt_with_secret(packet_contents_message, secret, checksum)
		send_data = peer_id + local_public_key + checksum + encrypted_message
		#print(f"checksum: {checksum.hex()}")
		#print(f"send_data: {send_data.hex()}")
		
		# send
		self.sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
		self.sock.settimeout(3)
		self.sock.connect((host, port))
		self.sock.send(send_data)
		
		read_data, host_port = self.sock.recvfrom(1024)
		#print(f"read_data: {len(read_data)}, {read_data.hex()}")
		byte_stream = ByteStream(read_data)
		read_local_id = byte_stream.read(32)
		read_public_key = byte_stream.read(32)
		read_checksum = byte_stream.read(32)
		read_encrypted_message = byte_stream.read()
		new_secret = self.get_secret(self.local_private_key, read_public_key)
		read_message = self.aes_decrypt_with_secret(read_encrypted_message, new_secret, read_checksum)
		checksum = self.sha256(read_message)
		if read_local_id != local_id:
			raise Exception("connect error: read_local_id != local_id")
		if read_checksum != checksum:
			raise Exception("connect error: read_checksum != checksum")
		#print(f"read_local_id: {read_local_id == local_id}")
		#print(f"read_checksum: {read_checksum == checksum}")
		print(f"read_message: {read_message.hex()}")
		
		byte_stream = ByteStream(read_message)
		read_scheme_id = byte_stream.read(4)
		read_scheme = self.tl_schemes.get_scheme_by_id(read_scheme_id)
		data = read_scheme.deserialize(byte_stream)
		print(f"data: {data}")
	#end define
	
	def sign_message(self, private_key, message):
		signing_key = SigningKey(private_key)
		signed_message = signing_key.sign(message)[:64]
		return signed_message
	#end define
	
	def get_secret(self, local_private_key, peer_public_key):
		local_signing_key = SigningKey(local_private_key)
		local_private_key_x25519 = local_signing_key.to_curve25519_private_key().encode()
		
		# create secret key
		peer_verify_key = VerifyKey(peer_public_key) # 32 bytes
		peer_public_key_x25519 = peer_verify_key.to_curve25519_public_key().encode()
		secret = x25519.scalar_mult(local_private_key_x25519, peer_public_key_x25519)
		return secret
	#end define
	
	def get_public_key(self, private_key):
		signing_key = SigningKey(private_key)
		public_key = signing_key.verify_key.encode()
		return public_key
	#end define
	
	def aes_encrypt_with_secret(self, data, secret, checksum):
		key = secret[0:16] + checksum[16:32]
		nonce = checksum[0:4] + secret[20:32]
		cipher = self.create_aes_cipher(key, nonce)
		encrypted_data = cipher.encrypt(data)
		return encrypted_data
	#end define
	
	def aes_decrypt_with_secret(self, encrypted_data, secret, checksum):
		key = secret[0:16] + checksum[16:32]
		nonce = checksum[0:4] + secret[20:32]
		cipher = self.create_aes_cipher(key, nonce)
		data = cipher.decrypt(encrypted_data)
		return data
	#end define
	
	def create_aes_cipher(self, key, nonce):
		ctrInitValue = int.from_bytes(nonce, "big")
		ctr = Counter.new(128, initial_value=ctrInitValue)
		cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
		return cipher
	#end define
	
	def get_id(self, pubkey):
		magic = bytes.fromhex("c6b41348") # 0x4813b4c6
		result = self.sha256(magic + pubkey)
		return result
	#end define
	
	def sha256(self, data):
		return hashlib.sha256(data).digest()
	#end define
#end class

class AdnlTcpClient:
	def __init__(self):
		self.local = None
		self.sock = None
		self.local_priv = None
		self.local_pub = None
		self.rx_key = None
		self.tx_key = None
		self.rx_nonce = None
		self.tx_nonce = None
		self.rx_cipher = None
		self.tx_cipher = None
		self.tl_schemes = TlSchemes()
		self.tlb_schemes = TlbSchemes()
		self.load_tl_schemes()
		self.load_tlb_schemes()
	#end define
	
	def load_tl_schemes(self):
		dir = "/usr/src/ton/tl/generate/scheme/"
		if os.path.isdir(dir):
			self.tl_schemes.load_schemes(dir)
		else:
			raise Exception("Tl schemes not found. Use command: `cd /usr/src && git clone https://github.com/ton-blockchain/ton`")
	#end define
	
	def load_tlb_schemes(self):
		dir = "/usr/src/ton/crypto/block/"
		if os.path.isdir(dir):
			self.tlb_schemes.load_schemes(dir)
		else:
			raise Exception("Tlb schemes not found. Use command: `cd /usr/src && git clone https://github.com/ton-blockchain/ton`")
	#end define
	
	def add_log(self, text, type):
		if self.local:
			self.local.AddLog(text, type)
		else:
			print(text)
	#end define
	
	def create_channel_keys(self):
		# create local private key
		sk = SigningKey.generate() # 32 bytes
		self.channel_local_priv = sk.encode() # ed25519
		self.channel_local_pub = sk.verify_key.encode() # ed25519
	#end define
	
	def get_signed_address_list(self):
		send_scheme = self.tl_schemes.get_scheme_by_name("dht.getSignedAddressList")
		send_data = send_scheme.id
	#end define

	def connect(self, host, port, pubkey):
		handshake = self.create_handshake(pubkey)

		# create rx, tx cipher
		self.rx_cipher = self.create_aes_cipher(self.rx_key, self.rx_nonce)
		self.tx_cipher = self.create_aes_cipher(self.tx_key, self.tx_nonce)

		# send handshake
		self.sock = socket.socket()
		self.sock.settimeout(3)
		self.sock.connect((host, port))
		self.sock.send(handshake)

		self.get_datagram()
	#end define

	def create_handshake(self, pubkey_b64):
		peer_pub = base64.b64decode(pubkey_b64) # 32 bytes, ed25519
		peer_id = self.get_id(peer_pub) # 32 bytes
		
		# create local private key
		sk = SigningKey.generate() # 32 bytes
		local_priv = sk.encode() # ed25519
		local_pub = sk.verify_key.encode() # ed25519
		private_key = sk.to_curve25519_private_key().encode() # x25519

		# create secret key
		peer_verify_key = VerifyKey(peer_pub) # 32 bytes
		peer_public_key = peer_verify_key.to_curve25519_public_key().encode() # x25519
		secret = x25519.scalar_mult(private_key, peer_public_key) # x25519

		# create aes_params
		self.rx_key = secrets.token_bytes(32) # 32 bytes
		self.tx_key = secrets.token_bytes(32) # 32 bytes
		self.rx_nonce = secrets.token_bytes(16) # 16 bytes
		self.tx_nonce = secrets.token_bytes(16) # 16 bytes
		padding = secrets.token_bytes(64) # 64 bytes
		aes_params = self.rx_key + self.tx_key + self.rx_nonce + self.tx_nonce + padding # 160 bytes

		#create handshake
		checksum = self.sha256(aes_params) # 32 bytes
		encrypted_aes_params = self.aes_encrypt_with_secret(aes_params, secret)
		handshake = peer_id + local_pub + checksum + encrypted_aes_params # 256 bytes
		return handshake
	#end define

	def get_datagram(self):
		data = self.receive(4)
		dlen = int.from_bytes(data, "little")
		data = self.receive(dlen)
		nonce = data[0:32]
		buffer = data[32:-32]
		checksum = data[-32:]
		hash = self.sha256(nonce + buffer)
		if hash != checksum:
			print("buffer:", buffer.hex())
			print("hash:", hash.hex())
			print("checksum:", checksum.hex())
			raise Exception("get_datagram error: Checksum does not match")
		return buffer
	#end define

	def send_datagram(self, data):
		nonce = secrets.token_bytes(32)
		checksum = self.sha256(nonce + data)
		dlen = len(nonce + data + checksum)
		dlen = dlen.to_bytes(4, byteorder="little")
		sdata = dlen + nonce + data + checksum
		self.send(sdata)
	#end define

	def send(self, data):
		sdata = self.tx_cipher.encrypt(data)
		self.sock.send(sdata)
	#end define

	def receive(self, dlen):
		rdata = self.sock.recv(dlen)
		if len(rdata) == 0:
			raise Exception("receive error: no data")
		result = self.rx_cipher.decrypt(rdata)
		return result
	#end define

	def aes_encrypt_with_secret(self, aes_params, secret):
		hash = self.sha256(aes_params)
		key = secret[0:16] + hash[16:32]
		nonce = hash[0:4] + secret[20:32]
		cipher = self.create_aes_cipher(key, nonce)
		result = cipher.encrypt(aes_params)
		return result
	#end define

	def create_aes_cipher(self, key, nonce):
		ctrInitValue = int.from_bytes(nonce, "big")
		ctr = Counter.new(128, initial_value=ctrInitValue)
		cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
		return cipher
	#end define

	def sha256(self, data):
		return hashlib.sha256(data).digest()
	#end define

	def get_id(self, pubkey):
		magic = bytes.fromhex("c6b41348") # 0x4813b4c6
		result = self.sha256(magic + pubkey)
		return result
	#end define
	
	def get_method_id(self, method_name):
		# https://github.com/ton-blockchain/ton/blob/24dc184a2ea67f9c47042b4104bbb4d82289fac1/crypto/smc-envelope/SmartContract.h#L75
		buff = fastcrc.crc16.xmodem(method_name.encode("utf8"))
		result = (buff & 0xffff) | 0x10000
		return result
	#end define
	
	def align_bytes(self, data, alen=4):
		dlen = len(data)
		nlen = 0
		if dlen % alen != 0:
			nlen = alen - dlen % alen
		buff = bytes.fromhex("00")
		result = data + buff * nlen
		return result
	#end define
	
	def ping(self):
		# send
		send_scheme = self.tl_schemes.get_scheme_by_name("tcp.ping")
		random_id = secrets.token_bytes(8)
		send_data = send_scheme.id + random_id
		self.send_datagram(send_data)
		
		# get
		read_data = self.get_datagram()
		byte_stream = ByteStream(read_data)
		read_scheme_id = byte_stream.read(4)
		read_scheme = self.tl_schemes.get_scheme_by_id(read_scheme_id)
		data = read_scheme.deserialize(byte_stream)
		if data.random_id != Int(random_id):
			raise Exception("Adnl ping error: random_id does not match")
		self.add_log("ping - ok", "debug")
	#end define
	
	def query(self, data):
		# send
		send_scheme = self.tl_schemes.get_scheme_by_name("adnl.message.query")
		query_id = secrets.token_bytes(32)
		dlen = tl_len(data)
		data = self.align_bytes(dlen + data)
		send_data = send_scheme.id + query_id + data
		self.send_datagram(send_data)
		#print(f"send_data: {send_data.hex()}")
		
		# get
		read_data = self.get_datagram()
		#print(f"read_data: {read_data.hex()}")
		byte_stream = ByteStream(read_data)
		read_scheme_id = byte_stream.read(4)
		read_scheme = self.tl_schemes.get_scheme_by_id(read_scheme_id)
		data = read_scheme.deserialize(byte_stream)
		if query_id.hex() != data.query_id:
			raise Exception("Adnl query error: query_id does not match")
		return data.answer
	#end define
	
	def lite_server_query(self, data):
		# send
		send_scheme = self.tl_schemes.get_scheme_by_name("liteServer.query")
		dlen = tl_len(data)
		data = self.align_bytes(dlen + data)
		send_data = send_scheme.id + data
		
		# get
		read_data = self.query(send_data)
		return read_data
	#end define
	
	def lite_server(self, function_name, **data):
		# send
		send_scheme = self.tl_schemes.get_scheme_by_name(f"liteServer.{function_name}")
		send_data = send_scheme.id + send_scheme.serialize(**data)
		
		# get
		read_data = self.lite_server_query(send_data)
		byte_stream = ByteStream(read_data)
		read_scheme_id = byte_stream.read(4)
		read_scheme = self.tl_schemes.get_scheme_by_id(read_scheme_id)
		result = read_scheme.deserialize(byte_stream, **data)
		if read_scheme.name == "liteServer.error":
			raise Exception(f"liteServer.error code: {result.code}, message: {result.message}")
		return result
	#end define
	
	def get_masterchain_info(self):
		"""
		liteServer.getMasterchainInfo = liteServer.MasterchainInfo;
		"""
		return self.lite_server("getMasterchainInfo")
	#end define
	
	def get_time(self):
		"""
		liteServer.getTime = liteServer.CurrentTime;
		"""
		return self.lite_server("getTime")
	#end define
	
	def get_block(self, block_id_ext=None):
		"""
		block#11ef55aa global_id:int32 info:^BlockInfo value_flow:^ValueFlow state_update:^(MERKLE_UPDATE ShardState) extra:^BlockExtra = Block;
		"""
		if block_id_ext is None:
			data = self.lite_server("getMasterchainInfo")
			block_id_ext = data.last
		#end if
		
		block_data = self.lite_server("getBlock", id=block_id_ext)
		data_cell = deserialize_boc(block_data.data)
		data = self.tlb_schemes.deserialize(data_cell, expected="Block")
		return data
	#end define
	
	def get_state(self, block_id_ext=None):
		"""
		_ ShardStateUnsplit = ShardState;
		split_state#5f327da5 left:^ShardStateUnsplit right:^ShardStateUnsplit = ShardState;
		"""
		if block_id_ext is None:
			data = self.lite_server("getMasterchainInfo")
			block_id_ext = data.last
		#end if
		
		block_data = self.lite_server("getState", id=block_id_ext)
		data_cell = deserialize_boc(block_data.data)
		data = self.tlb_schemes.deserialize(data_cell, expected="ShardState")
		return data
	#end define
	
	def get_block_header(self, block_id_ext=None):
		"""
		block_info#9bc7a987 version:uint32 not_master:(## 1) after_merge:(## 1) before_split:(## 1) after_split:(## 1) want_split:Bool want_merge:Bool key_block:Bool vert_seqno_incr:(## 1) flags:(## 8) 
		{ flags <= 1 } seq_no:# vert_seq_no:# { vert_seq_no >= vert_seqno_incr } { prev_seq_no:# } { ~prev_seq_no + 1 = seq_no } shard:ShardIdent gen_utime:uint32 start_lt:uint64 end_lt:uint64 gen_validator_list_hash_short:uint32
		gen_catchain_seqno:uint32 min_ref_mc_seqno:uint32 prev_key_block_seqno:uint32 gen_software:flags . 0?GlobalVersion master_ref:not_master?^BlkMasterInfo prev_ref:^(BlkPrevInfo after_merge) prev_vert_ref:vert_seqno_incr?^(BlkPrevInfo 0)
		= BlockInfo;
		"""
		if block_id_ext is None:
			data = self.lite_server("getMasterchainInfo")
			block_id_ext = data.last
		#end if
		
		mode = self.set_flags("mode.null")
		block_header_data = self.lite_server("getBlockHeader", id=block_id_ext, mode=mode)
		data_cell = deserialize_boc(block_header_data.header_proof)
		print(f"get_block_header data_cell: {json.dumps(cell2dict(data_cell, True), indent=4)}")
		data = self.tlb_schemes.deserialize(data_cell, expected="BlockInfo")
		return data
	#end define
	
	def set_flags(self, flags):
		sep = ' '
		mode_len = 32
		mode_bin = BitArray(mode_len)
		flags = flags.replace('.', sep)
		flags = flags.replace(',', sep)
		flags = flags.split(sep)
		for item in flags:
			if item.isdigit():
				index = mode_len - int(item) - 1
				mode_bin[index] = True
		return mode_bin.uint
	#end define
	
	def run_smc_method(self, input_addr, method_name, params=None, block_id_ext=None):
		"""
		TODO:	TLB	-> VmStack
		liteServer.runSmcMethod mode:# id:tonNode.blockIdExt account:liteServer.accountId method_id:long params:bytes = liteServer.RunMethodResult;
		liteServer.runMethodResult mode:# id:tonNode.blockIdExt shardblk:tonNode.blockIdExt shard_proof:mode.0?bytes proof:mode.0?bytes state_proof:mode.1?bytes init_c7:mode.3?bytes lib_extras:mode.4?bytes exit_code:int result:mode.2?bytes = liteServer.RunMethodResult;
		"""
		if block_id_ext is None:
			data = self.lite_server("getMasterchainInfo")
			block_id_ext = data.last
		#end if
		
		mode = self.set_flags("mode.0.2")
		workchain, addr = ParseAddr(input_addr)
		account_id = {"workchain":workchain, "id":addr}
		method_id = self.get_method_id(method_name)
		params_cell = self.tlb_schemes.serialize(required="VmStack", params=params)
		params_boc = serialize_boc(params_cell)
		data = self.lite_server("runSmcMethod", mode=mode, id=block_id_ext, account=account_id, method_id=method_id, params=params_boc)
		
		# data.proof # TODO
		# data.shard_proof # TODO
		data_cell = deserialize_boc(data.result)
		print(f"run_smc_method data_cell: {json.dumps(cell2dict(data_cell, True), indent=4)}")
		data = self.tlb_schemes.deserialize(data_cell, expected="VmStack")
		return data
	#end define
	
	def get_account_state(self, input_addr, block_id_ext=None):
		"""
		liteServer.getAccountState id:tonNode.blockIdExt account:liteServer.accountId = liteServer.AccountState;
		"""
		if block_id_ext is None:
			data = self.lite_server("getMasterchainInfo")
			block_id_ext = data.last
		#end if
		
		workchain, addr = ParseAddr(input_addr)
		account_id = {"workchain":workchain, "id":addr}
		account_data = self.lite_server("getAccountState", id=block_id_ext, account=account_id)
		# account_data.proof # TODO
		# account_data.shard_proof # TODO
		state_cell = deserialize_boc(account_data.state)
		account_state = self.tlb_schemes.deserialize(state_cell, expected="Account")
		return account_state
	#end define
	
	def get_all_shards_info(self, block_id_ext=None):
		"""
		liteServer.getAllShardsInfo id:tonNode.blockIdExt = liteServer.AllShardsInfo;
		"""
		if block_id_ext is None:
			data = self.lite_server("getMasterchainInfo")
			block_id_ext = data.last
		#end if
		
		shards_data = self.lite_server("getAllShardsInfo", id=block_id_ext)
		# shards_data.proof # TODO
		data_cell = deserialize_boc(shards_data.data)
		data = self.tlb_schemes.deserialize(data_cell, expected="ShardHashes")
		return data
	#end define
	
	def get_config_params(self, params, block_id_ext=None):
		"""
		liteServer.getConfigParams mode:# id:tonNode.blockIdExt param_list:(vector int) = liteServer.ConfigInfo;
		liteServer.configInfo mode:# id:tonNode.blockIdExt state_proof:bytes config_proof:bytes = liteServer.ConfigInfo;
		"""
		if type(params) is int:
			param_list = [params]
		elif type(params) is list:
			param_list = params
		if block_id_ext is None:
			data = self.lite_server("getMasterchainInfo")
			block_id_ext = data.last
		#end if
		
		mode = self.set_flags("mode.null")
		config_params_data = self.lite_server("getConfigParams", id=block_id_ext, mode=mode, param_list=param_list)
		# config_params_data.state_proof # TODO
		data_cell = deserialize_boc(config_params_data.config_proof)
		data_cell = data_cell.refs[0]
		print(f"get_config_params data_cell: {json.dumps(cell2dict(data_cell, True), indent=4)}")
		data = self.tlb_schemes.deserialize(data_cell, expected="???")
		print(f"get_config_params data: {data}")
		return data
	#end define
	
	def get_last_transactions(self, input_addr, count=10):
		"""
		liteServer.getTransactions count:# account:liteServer.accountId lt:long hash:int256 = liteServer.TransactionList;
		liteServer.transactionList ids:(vector tonNode.blockIdExt) transactions:bytes = liteServer.TransactionList;
		"""
		
		workchain, addr = ParseAddr(input_addr)
		account_id = {"workchain":workchain, "id":addr}
		account_state = self.get_account_state(input_addr)
		transactions_data = self.lite_server("getTransactions", count=count, account=account_id, lt=33781466000001, hash="EDC177F94D0193E81996CDC312CE7274B9316EBC985440E0D0B388453B77DF7E")
		# transactions_data.ids # TODO
		transaction_cells = deserialize_boc(transactions_data.transactions)
		
		result = list()
		for transaction_cell in transaction_cells:
			data = self.tlb_schemes.deserialize(transaction_cell, expected="Transaction")
			result.append(data)
		#end for
		return result
	#end define
#end class

def tests():
	"""
	Test commands from lite-client
	"""
	
	host = "127.0.0.1"
	port = 23227
	pubkey = "DuCFdD/LoCi9HywfMsFrKxg+G0nKPv3RuLNrQVCA1lk="

	adnl = AdnlTcpClient()
	adnl.connect(host, port, pubkey)
	adnl.ping()

	# time - Get server time
	data = adnl.get_time()
	print("get_time:", json.dumps(data, indent=4))

	# last - Get last block and state info from server
	data = adnl.get_masterchain_info()
	print("get_masterchain_info:", json.dumps(data, indent=4))
	print(f"data.last.seqno: {data.last.seqno}")
	
	# sendfile - Load a serialized message from <filename> and send it to server

	# getaccount - Loads the most recent state of specified account
	data = adnl.get_account_state("EQCD39VS5jcptHL8vMjEXrzGaRcCVYto7HUn4bpAOg8xqB2N")
	print("get_account_state:", json.dumps(data, indent=4))
	
	# runmethod - Runs GET method <method-id> of account <addr> with specified parameters
	#data = adnl.run_smc_method("kQBL2_3lMiyywU17g-or8N7v9hDmPCpttzBPE2isF2GTziky", "mult", [5, 4])
	#data = adnl.run_smc_method("EQCD39VS5jcptHL8vMjEXrzGaRcCVYto7HUn4bpAOg8xqB2N", "seqno")
	#data = adnl.run_smc_method("EQCD39VS5jcptHL8vMjEXrzGaRcCVYto7HUn4bpAOg8xqB2N", "get_public_key")
	#print("run_smc_method:", json.dumps(data, indent=4))
	#print("run_smc_method:", data)
	
	# dnsresolve - Resolves a domain starting from root dns smart contract
	
	
	# dnsresolvestep - Resolves a subdomain using dns smart contract <addr>
	
	
	# allshards - Shows shard configuration from the most recent masterchain state or from masterchain state corresponding to <block-id-ext>
	data = adnl.get_all_shards_info()
	print("get_all_shards_info:", json.dumps(data, indent=4))
	
	# getconfig [<param>...]  Shows specified or all configuration parameters from the latest masterchain state
	#data = adnl.get_config_params(8)
	#print("get_config_params:", json.dumps(data, indent=4))
	
	# gethead - Shows block header for <block-id-ext>
	data = adnl.get_block_header()
	print("get_block_header:", json.dumps(data, indent=4))
	
	# getblock - Downloads block
	data = adnl.get_block()
	print("get_block:", json.dumps(data, indent=4))
	#print("get_block:", data)
	
	# DELETE
	# getstate - Downloads state corresponding to specified block
	#data = adnl.get_state()
	#print("get_state:", json.dumps(data, indent=4))
	#print("get_state:", data)
	
	# dumptrans - Dumps one transaction of specified account
	
	
	# lasttrans - Shows or dumps specified transaction and several preceding ones
	data = adnl.get_last_transactions("EQCD39VS5jcptHL8vMjEXrzGaRcCVYto7HUn4bpAOg8xqB2N")
	print("get_last_transactions:", json.dumps(data, indent=4))
	#print("get_last_transactions:", data)
	
	# listblocktrans - Lists block transactions, starting immediately after or before the specified one
	
	
	# byseqno - Looks up a block by workchain, shard and seqno, and shows its header
	
	
	# bylt - Looks up a block by workchain, shard and logical time, and shows its header
	
	
	# byutime - Looks up a block by workchain, shard and creation time, and shows its header
	
	
	# creatorstats - Lists block creator statistics by validator public key
	
	
	# recentcreatorstats - Lists block creator statistics updated after <start-utime> by validator public key
	
	
	# checkload - Checks whether all validators worked properly during specified time interval, and optionally saves proofs into <savefile-prefix>-<n>.boc
	
	
	# loadproofcheck - Checks a validator misbehavior proof previously created by checkload
	
	
	# pastvalsets     Lists known past validator set ids and their hashes
	
	
	# savecomplaints - Saves all complaints registered for specified validator set id into files <filename-pfx><complaint-hash>.boc
	
	
	# complaintprice - Computes the price (in nanograms) for creating a complaint
	
	
#end define

def tests2():
	host = "65.21.7.173"
	port = 15813
	pubkey = "fZnkoIAxrTd4xeBgVpZFRm5SvVvSx7eN3Vbe8c83YMk="
	
	adnl = AdnlUdpClient()
	adnl.connect(host, port, pubkey)



###
### Start of the program
###

if __name__ == "__main__":
	tests()
	#tests2()
#end if


