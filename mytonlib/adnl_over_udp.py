#!/usr/bin/env python3
# -*- coding: utf_8 -*-

from os.path import isdir, dirname, join
import time
import json
import random
import base64
import socket
import x25519 # pip3 install x25519
import hashlib
import secrets
import fastcrc # pip3 install fastcrc
#import urllib.request
import threading
from io import BytesIO as ByteStream
from bitstring import BitArray # pip3 install bitstring
from nacl.signing import SigningKey, VerifyKey # pip3 install pynacl
from Crypto.Cipher import AES # pip3 install pycryptodome
from Crypto.Util import Counter

from .tl import TlSchemes, Int, tl_len
from .tlb import TlbSchemes
from .boc import serialize_boc, deserialize_boc
from .utils import parse_addr, hex2dec, parse_pubkey
from .mytypes import Dict, Thread
#from .tvm.tvm import TVM

class AdnlUdpClient():
	def __init__(self):
		self.local = None
		self.sock = None
		self.local_private_key = secrets.token_bytes(32)
		self.channel_private_key = secrets.token_bytes(32)
		self.channels = list()
		self.tl_schemes = TlSchemes()
		self.tlb_schemes = TlbSchemes()
		self.load_tl_schemes()
		self.load_tlb_schemes()
	#end define
	
	def load_tl_schemes(self):
		dir = "/usr/src/ton/tl/generate/scheme/"
		if isdir(dir):
			self.tl_schemes.load_schemes(dir)
		else:
			raise Exception("Tl schemes not found. Use command: `cd /usr/src && git clone https://github.com/ton-blockchain/ton`")
	#end define
	
	def load_tlb_schemes(self):
		dir = "/usr/src/ton/crypto/block/"
		if isdir(dir):
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

	def read_socket(self, connect_data):
		read_data, host_port = self.sock.recvfrom(1024)
		#print(f"read_data: {len(read_data)}, {read_data.hex()}")
		byte_stream = ByteStream(read_data)
		read_local_id = byte_stream.read(32)
		read_public_key = byte_stream.read(32)
		read_checksum = byte_stream.read(32)
		read_encrypted_message = byte_stream.read()
		new_secret = self.get_secret(self.local_private_key, read_public_key)
		read_message = self.aes_decrypt_with_secret(read_encrypted_message, new_secret, read_checksum)
		checksum = self._sha256(read_message)
		if read_local_id != connect_data.local_id:
			raise Exception("connect error: read_local_id != local_id")
		if read_checksum != checksum:
			raise Exception("connect error: read_checksum != checksum")
		#print(f"read_message: {read_message.hex()}")
		return read_message
	#end define

	def ping(self, host, port, pubkey):
		return self.ping_cpp_node(host, port, pubkey) or self.ping_tonutils_node(host, port, pubkey)
	#end define

	def ping_tonutils_node(self, host, port, pubkey):
		try:
			self.do_ping_tonutils_node(host, port, pubkey)
			return True
		except:
			return False
	#end define

	def ping_cpp_node(self, host, port, pubkey):
		try:
			self.do_ping_cpp_node(host, port, pubkey)
			return True
		except TimeoutError:
			return False
	#end define

	def do_ping_tonutils_node(self, host, port, pubkey):
		long_start = -9223372036854775808
		long_end = 9223372036854775807
		connect_data = self.create_connect_keys(host, port, pubkey)

		# create Ping message: adnl.ping | dht.ping | storage.ping
		random_int = random.randint(long_start, long_end)
		ping_message = Dict(scheme_name="adnl.ping", value=random_int)
		#ping_message = Dict(scheme_name="dht.ping", random_id=random_int)
		#ping_message = Dict(scheme_name="storage.ping", session_id=random_int)

		# create connect_message
		connect_message = self.create_connect_message(connect_data, message=ping_message)

		# send and read
		self.sock.send(connect_message)
		read_message = self.read_socket(connect_data)
	#end define

	def do_ping_cpp_node(self, host, port, pubkey):
		connect_data = self.create_connect_keys(host, port, pubkey)

		# create createChannel message
		create_channel_message = Dict(scheme_name="adnl.message.createChannel", key=connect_data.channel_public_key.hex(), date=connect_data.timestamp)

		# create getSignedAddressList message
		query_id = secrets.token_bytes(32).hex() # 32 bytes
		scheme = self.tl_schemes.get_scheme_by_name("dht.getSignedAddressList")
		get_signed_address_list_message = Dict(scheme_name="adnl.message.query", query_id=query_id, query=scheme.id)

		# create connect_message
		connect_message = self.create_connect_message(connect_data, messages=[create_channel_message, get_signed_address_list_message])

		# send and read
		self.sock.send(connect_message)
		read_message = self.read_socket(connect_data)
	#end define

	def create_connect_keys(self, host, port, pubkey):
		connect_data = Dict()
		connect_data.timestamp = int(time.time())
		connect_data.peer_public_key = parse_pubkey(pubkey)
		connect_data.peer_id = self._get_id(connect_data.peer_public_key)
		
		connect_data.local_public_key = self.get_public_key(self.local_private_key)
		connect_data.channel_public_key = self.get_public_key(self.channel_private_key)
		connect_data.local_id = self._get_id(connect_data.local_public_key)
		
		# create PublicKey message
		connect_data.public_key_message = Dict(scheme_name="pub.ed25519", key=connect_data.local_public_key.hex())

		# create socket
		self.sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
		self.sock.settimeout(0.9)
		self.sock.connect((host, port))

		return connect_data
	#end define

	def create_connect_message(self, connect_data, message=None, messages=None):
		# create addressList message
		address_list_message = Dict(scheme_name="adnl.addressList", addrs=[], version=connect_data.timestamp, reinit_date=connect_data.timestamp, priority=0, expire_at=0)

		# create PacketContents message
		scheme = self.tl_schemes.get_scheme_by_name("adnl.packetContents")
		packet_contents = Dict(
			rand1 = secrets.token_bytes(15),
			#flags = self.set_flags("flags.0,3,4,6,7,8,10"),
			_from = connect_data.public_key_message,
			#messages = [create_channel_message, get_signed_address_list_message],
			address = address_list_message,
			seqno = 1,
			confirm_seqno = 0,
			recv_addr_list_version = connect_data.timestamp,
			reinit_date = connect_data.timestamp,
			dst_reinit_date = 0,
			signature = None,
			rand2 = secrets.token_bytes(15)
		)
		if message != None:
			packet_contents.flags = self.set_flags("flags.0,2,4,6,7,8,10")
			packet_contents.message = message
		if messages != None:
			packet_contents.flags = self.set_flags("flags.0,3,4,6,7,8,10")
			packet_contents.messages = messages
		packet_contents_message = scheme.id + scheme.serialize(**packet_contents)
		
		# create PacketContents message with signature
		if message != None:
			packet_contents.flags = self.set_flags("flags.0,2,4,6,7,8,10,11")
		if messages != None:
			packet_contents.flags = self.set_flags("flags.0,3,4,6,7,8,10,11")
		packet_contents.signature = self.sign_message(self.local_private_key, packet_contents_message)
		buff = self.sign_message(self.local_private_key, packet_contents_message)
		packet_contents_message = scheme.id + scheme.serialize(**packet_contents)
		#print(f"packet_contents_message: {packet_contents_message.hex()}")
		
		checksum = self._sha256(packet_contents_message)
		secret = self.get_secret(self.local_private_key, connect_data.peer_public_key)
		encrypted_message = self._aes_encrypt_with_secret(packet_contents_message, secret, checksum)
		send_message = connect_data.peer_id + connect_data.local_public_key + checksum + encrypted_message
		#print(f"send_message: {send_message.hex()}")
		return send_message
	#end define
	
	def connect(self, host, port, peer_public_key_b64):
		timestamp = int(time.time())
		peer_public_key = base64.b64decode(peer_public_key_b64)
		peer_id = self._get_id(peer_public_key)
		
		local_public_key = self.get_public_key(self.local_private_key)
		channel_public_key = self.get_public_key(self.channel_private_key)
		local_id = self._get_id(local_public_key)
		
		# create PublicKey message
		public_key_message = Dict(scheme_name="pub.ed25519", key=local_public_key.hex())
		
		# create createChannel message
		create_channel_message = Dict(scheme_name="adnl.message.createChannel", key=channel_public_key.hex(), date=timestamp)
		
		# create getSignedAddressList message
		query_id = secrets.token_bytes(32).hex() # 32 bytes
		scheme = self.tl_schemes.get_scheme_by_name("dht.getSignedAddressList")
		get_signed_address_list_message = Dict(scheme_name="adnl.message.query", query_id=query_id, query=scheme.id)
		
		# create addressList message
		address_list_message = Dict(scheme_name="adnl.addressList", addrs=[], version=timestamp, reinit_date=timestamp, priority=0, expire_at=0)
		
		# create PacketContents message
		scheme = self.tl_schemes.get_scheme_by_name("adnl.packetContents")
		packet_contents = Dict(
			rand1 = secrets.token_bytes(15),
			flags = self.set_flags("flags.0,3,4,6,7,8,10"),
			_from = public_key_message,
			messages = [create_channel_message, get_signed_address_list_message],
			address = address_list_message,
			seqno = 1,
			confirm_seqno = 0,
			recv_addr_list_version = timestamp,
			reinit_date = timestamp,
			dst_reinit_date = 0,
			signature = None,
			rand2 = secrets.token_bytes(15)
		)
		packet_contents_message = scheme.id + scheme.serialize(**packet_contents)
		
		# create PacketContents message with signature
		packet_contents.flags = self.set_flags("flags.0,3,4,6,7,8,10,11")
		packet_contents.signature = self.sign_message(self.local_private_key, packet_contents_message)
		buff = self.sign_message(self.local_private_key, packet_contents_message)
		packet_contents_message = scheme.id + scheme.serialize(**packet_contents)
		#print(f"packet_contents_message: {packet_contents_message.hex()}")
		
		checksum = self._sha256(packet_contents_message)
		secret = self.get_secret(self.local_private_key, peer_public_key)
		encrypted_message = self._aes_encrypt_with_secret(packet_contents_message, secret, checksum)
		send_data = peer_id + local_public_key + checksum + encrypted_message
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
		checksum = self._sha256(read_message)
		if read_local_id != local_id:
			raise Exception("connect error: read_local_id != local_id")
		if read_checksum != checksum:
			raise Exception("connect error: read_checksum != checksum")
		#print(f"read_message: {read_message.hex()}")
		
		byte_stream = ByteStream(read_message)
		read_scheme_id = byte_stream.read(4)
		read_scheme = self.tl_schemes.get_scheme_by_id(read_scheme_id)
		data = read_scheme.deserialize(byte_stream)
		
		confirm_channel_message = self.get_message_by_name(data.messages, "adnl.message.confirmChannel")
		print(f"confirm_channel_message: {confirm_channel_message}")
		channel_peer_public_key = bytes.fromhex(confirm_channel_message.key)
		channel_secret = self.get_secret(self.channel_private_key, channel_peer_public_key)
		channel_secret2 = channel_secret[::-1]
		print(f"channel_secret: {channel_secret.hex()}")
		print(f"channel_secret2: {channel_secret2.hex()}")
		if local_id > peer_id:
			channel_tx_key = channel_secret
			channel_rx_key = channel_secret2
		elif local_id < peer_id:
			channel_tx_key = channel_secret2
			channel_rx_key = channel_secret
		else:
			channel_tx_key = channel_secret
			channel_rx_key = channel_secret
		#end if
		print(f"channel_tx_key: {channel_tx_key.hex()}")
		print(f"channel_rx_key: {channel_rx_key.hex()}")
		channel = Dict()
		channel["tx_key"] = channel_tx_key
		channel["rx_key"] = channel_rx_key
		self.channels.append(channel)
		
		# send new message into channel
		scheme = self.tl_schemes.get_scheme_by_name("adnl.packetContents")
		packet_contents = Dict(
			rand1 = secrets.token_bytes(15),
			flags = self.set_flags("flags.2,6,7"),
			message = get_signed_address_list_message,
			seqno = 2,
			confirm_seqno = 1,
			rand2 = secrets.token_bytes(15)
		)
		packet_contents_message = scheme.id + scheme.serialize(**packet_contents)
		checksum = self._sha256(packet_contents_message)
		encrypted_message = self._aes_encrypt_with_secret(packet_contents_message, channel_tx_key, checksum)
		#channel_tx_public_key = self.get_public_key(channel_tx_key)
		tx_public_key_id = self._get_id(channel_tx_key, scheme_name="pub.aes")
		send_data = tx_public_key_id + checksum + encrypted_message
		print(f"send_data: {send_data.hex()}")
		self.sock.send(send_data)
		read_data, host_port = self.sock.recvfrom(1024)
		print(f"read_data: {len(read_data)}, {read_data.hex()}")
	#end define
	
	def get_message_by_name(self, messages, name):
		for message in messages:
			message_name = message.get("@type")
			if message_name == name:
				return message
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
	
	def _aes_encrypt_with_secret(self, data, secret, checksum):
		key = secret[0:16] + checksum[16:32]
		nonce = checksum[0:4] + secret[20:32]
		cipher = self._create_aes_cipher(key, nonce)
		encrypted_data = cipher.encrypt(data)
		return encrypted_data
	#end define
	
	def aes_decrypt_with_secret(self, encrypted_data, secret, checksum):
		key = secret[0:16] + checksum[16:32]
		nonce = checksum[0:4] + secret[20:32]
		cipher = self._create_aes_cipher(key, nonce)
		data = cipher.decrypt(encrypted_data)
		return data
	#end define
	
	def _create_aes_cipher(self, key, nonce):
		ctrInitValue = int.from_bytes(nonce, "big")
		ctr = Counter.new(128, initial_value=ctrInitValue)
		cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
		return cipher
	#end define
	
	def _get_id(self, pubkey, scheme_name="pub.ed25519"):
		scheme = self.tl_schemes.get_scheme_by_name(scheme_name)
		result = self._sha256(scheme.id + pubkey)
		return result
	#end define
	
	def _sha256(self, data):
		return hashlib.sha256(data).digest()
	#end define
#end class