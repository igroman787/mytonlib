#!/usr/bin/env python3
# -*- coding: utf_8 -*-

from nacl.signing import SigningKey, VerifyKey
from nacl.exceptions import BadSignatureError
from .stack import get_from_tvm_list
from ..mytypes import Slice, Cell


def HASHCU(code_slice, tvm):
	item = get_from_tvm_list(tvm.stack, 0)
	if type(item) != Cell:
		raise Exception("HASHCU error: item is not a Cell")
	buff = item.hash()
	tvm.stack.append(buff.uint)
#end define

def HASHSU(code_slice, tvm):
	item = get_from_tvm_list(tvm.stack, 0)
	if type(item) != Slice:
		raise Exception("HASHCU error: item is not a Slice")
	buff = item.hash()
	tvm.stack.append(buff.uint)
#end define

def SHA256U(code_slice, tvm):
	item = get_from_tvm_list(tvm.stack, 0)
	if type(item) != Slice:
		raise Exception("SHA256U error: item is not a Slice")
	buff = item.hash()
	if buff.len % 8 != 0:
		raise Exception("SHA256U error: hash length is not a multiple of 8")
	tvm.stack.append(buff.uint)
#end define

def CHKSIGNU(code_slice, tvm):
	key_uint = get_from_tvm_list(tvm.stack, 0)
	signature_slice = get_from_tvm_list(tvm.stack, 0)
	hash_uint = get_from_tvm_list(tvm.stack, 0)
	key_bytes = int.to_bytes(key_uint, length=32, byteorder="big")
	signature_bytes = signature_slice.read(512).bytes
	hash_bytes = int.to_bytes(hash_uint, length=32, byteorder="big")
	verify_key = VerifyKey(key_bytes)
	print("CHKSIGNU")
	print("verify_key:", key_bytes.hex())
	print("signature_bytes:", signature_bytes.hex())
	print("hash_bytes:", hash_bytes.hex())
	try:
		verify_key.verify(hash_bytes, signature_bytes)
		result = -1
	except BadSignatureError:
		result = 0
	tvm.stack.append(result)
#end define

def CHKSIGNS(code_slice, tvm):
	key_uint = get_from_tvm_list(tvm.stack, 0)
	signature_slice = get_from_tvm_list(tvm.stack, 0)
	hash_uint = get_from_tvm_list(tvm.stack, 0)
	key_bytes = int.to_bytes(key_uint, length=32, byteorder="big")
	signature_bytes = signature_slice.read(512).bytes
	hash_bytes = int.to_bytes(hash_uint, length=32, byteorder="big")
	verify_key = VerifyKey(key_bytes)
	print("CHKSIGNS")
	print("verify_key:", key_bytes.hex())
	print("signature_bytes:", signature_bytes.hex())
	print("hash_bytes:", hash_bytes.hex())
	try:
		verify_key.verify(hash_bytes, signature_bytes)
		result = -1
	except BadSignatureError:
		result = 0
	tvm.stack.append(result)
#end define




