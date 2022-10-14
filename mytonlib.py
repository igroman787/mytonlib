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

from tl import TlSchemes, Int, TlLen
from tlb import TlbSchemes
from boc import serialize_boc, deserialize_boc
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

	def create_handshake(self, pubkey):
		other_pub = base64.b64decode(pubkey) # 32 bytes, ed25519
		other_id = self.get_id(other_pub) # 32 bytes

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
		checksum = self.sha256(aes_params) # 32 bytes
		encrypted_aes_params = self.aes_encrypt_with_secret(aes_params, secret)
		handshake = other_id + local_pub + checksum + encrypted_aes_params # 256 bytes
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
		dlen = TlLen(data)
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
		dlen = TlLen(data)
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
		result = read_scheme.deserialize(byte_stream)
		return result
	#end define
	
	def get_masterchain_info(self):
		return self.lite_server("getMasterchainInfo")
	#end define
	
	def get_time(self):
		return self.lite_server("getTime")
	#end define
	
	def get_block(self, block_id_ext=None):
		"""
		TODO: ^BlockInfo
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
		TODO: 
		get_scheme_by_id error: TL scheme '48e1a9bb' not found
		
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
	#end define
	
	def get_block_header(self, block_id_ext=None):
		"""
		TODO:
		block_info#9bc7a987 version:uint32 not_master:(## 1) after_merge:(## 1) before_split:(## 1) after_split:(## 1) want_split:Bool want_merge:Bool key_block:Bool vert_seqno_incr:(## 1) flags:(## 8) 
		{ flags <= 1 } seq_no:# vert_seq_no:# { vert_seq_no >= vert_seqno_incr } { prev_seq_no:# } { ~prev_seq_no + 1 = seq_no } shard:ShardIdent gen_utime:uint32 start_lt:uint64 end_lt:uint64 gen_validator_list_hash_short:uint32
		gen_catchain_seqno:uint32 min_ref_mc_seqno:uint32 prev_key_block_seqno:uint32 gen_software:flags . 0?GlobalVersion master_ref:not_master?^BlkMasterInfo prev_ref:^(BlkPrevInfo after_merge) prev_vert_ref:vert_seqno_incr?^(BlkPrevInfo 0)
		= BlockInfo;
		"""
		if block_id_ext is None:
			data = self.lite_server("getMasterchainInfo")
			block_id_ext = data.last
		#end if
		
		mode = self.set_mode("mode.null")
		block_header_data = self.lite_server("getBlockHeader", id=block_id_ext, mode=mode)
		data_cell = deserialize_boc(block_header_data.header_proof)
		data = self.tlb_schemes.deserialize(data_cell, expected="BlockInfo")
	#end define
	
	def set_mode(self, modes):
		sep = ' '
		mode_len = 32
		mode_bin = BitArray(mode_len)
		modes = modes.replace('.', sep)
		modes = modes.replace(',', sep)
		modes = modes.split(sep)
		for item in modes:
			if item.isdigit():
				indx = mode_len - int(item) - 1
				mode_bin[indx] = True
		return mode_bin.uint
	#end define
	
	def run_smc_method(self, input_addr, method_name, params=None, block_id_ext=None):
		"""
		TODO: 	TLB -> serialize
				BOC -> serialize_boc
		liteServer.runSmcMethod mode:# id:tonNode.blockIdExt account:liteServer.accountId method_id:long params:bytes = liteServer.RunMethodResult;
		"""
		if block_id_ext is None:
			data = self.lite_server("getMasterchainInfo")
			block_id_ext = data.last
		#end if
		
		mode = self.set_mode("mode.2")
		workchain, addr = ParseAddr(input_addr)
		account_id = {"workchain":workchain, "id":addr}
		method_id = self.get_method_id(method_name)
		params_cell = self.tlb_schemes.serialize(required="VmStack", params=params)
		params_boc = serialize_boc(params_cell)
		print(f"mode: {mode}, method_id: {method_id}, params_boc: {params_boc}")
		data = self.lite_server("runSmcMethod", mode=mode, id=block_id_ext, account=account_id, method_id=method_id, params=params_boc)
		return data.hex()
	#end define
	
	def get_account_state(self, input_addr, block_id_ext=None):
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
		TODO: TLB 	-> ShardHashes
					-> HashmapE
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
		TODO: -> vector int
		liteServer.getConfigParams mode:# id:tonNode.blockIdExt param_list:(vector int) = liteServer.ConfigInfo;
		"""
		if type(params) is int:
			param_list = [params]
		elif type(params) is list:
			param_list = params
		if block_id_ext is None:
			data = self.lite_server("getMasterchainInfo")
			block_id_ext = data.last
		#end if
		
		mode = self.set_mode("mode.null")
		config_params_data = self.lite_server("getConfigParams", id=block_id_ext, mode=mode, param_list=param_list)
	#end define
#end class

def tests():
	"""
	Test commands from lite-client
	"""
	
	host = "127.0.0.1"
	port = 23227
	pubkey = "DuCFdD/LoCi9HywfMsFrKxg+G0nKPv3RuLNrQVCA1lk="

	adnl = Adnl()
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
	data = adnl.run_smc_method("kQBL2_3lMiyywU17g-or8N7v9hDmPCpttzBPE2isF2GTziky", "mult", [5, 4])
	print("run_smc_method:", json.dumps(data, indent=4))
	
	# dnsresolve - Resolves a domain starting from root dns smart contract
	
	
	# dnsresolvestep - Resolves a subdomain using dns smart contract <addr>
	
	
	# allshards - Shows shard configuration from the most recent masterchain state or from masterchain state corresponding to <block-id-ext>
	#data = adnl.get_all_shards_info()
	#print("get_all_shards_info:", json.dumps(data, indent=4))
	#print("get_all_shards_info:", data)
	
	# getconfig [<param>...]  Shows specified or all configuration parameters from the latest masterchain state
	#data = adnl.get_config_params(1)
	#print("get_config_params:", json.dumps(data, indent=4))
	
	# gethead - Shows block header for <block-id-ext>
	#data = adnl.get_block_header()
	#print("get_block_header:", json.dumps(data, indent=4))
	
	# getblock - Downloads block
	#data = adnl.get_block()
	#print("get_block:", json.dumps(data, indent=4))
	#print("get_block:", data)
	
	# getstate - Downloads state corresponding to specified block
	#data = adnl.get_state()
	#print("get_state:", json.dumps(data, indent=4))
	#print("get_state:", data)
	
	# dumptrans - Dumps one transaction of specified account
	
	
	# lasttrans - Shows or dumps specified transaction and several preceding ones
	
	
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



###
### Start of the program
###

if __name__ == "__main__":
	tests()
#end if


