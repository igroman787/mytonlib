#!/usr/bin/env python3
# -*- coding: utf_8 -*-

import os
import binascii
from io import BytesIO as ByteStream
from mytypes import Dict


class TlSchemes:
	def __init__(self):
		self.schemes_names = dict()
		self.schemes_ids = dict()
	#end define
	
	def load_schemes(self, filepath):
		if os.path.isfile(filepath):
			self.load_schemes_from_file(filepath)
		elif os.path.isdir(filepath):
			self.load_schemes_from_dir(filepath)
	#end define
	
	def load_schemes_from_file(self, filepath):
		file = open(filepath, "rt")
		text = file.read()
		file.close()
		lines = text.split('\n')
		for line in lines:
			scheme = TlScheme(self, line)
			if scheme.name == None:
				continue
			self.schemes_names[scheme.name] = scheme
			self.schemes_ids[scheme.id] = scheme.name
		#end for
	#end define
	
	def load_schemes_from_dir(self, dir):
		for file in os.listdir(dir):
			if file.endswith(".tl"):
				filepath = dir + file
				self.load_schemes_from_file(filepath)
	#end define
	
	def get_scheme_by_name(self, scheme_name):
		result = self.schemes_names.get(scheme_name)
		if result is None:
			raise Exception(f"get_scheme_by_name error: scheme '{scheme_name}' not found")
		return result
	#end define
	
	def get_scheme_by_id(self, id):
		scheme_name = self.schemes_ids.get(id)
		result = self.schemes_names.get(scheme_name)
		if result is None:
			raise Exception(f"get_scheme_by_id error: scheme '{id.hex()}' not found")
		return result
	#end define
#end class

class TlScheme:
	def __init__(self, schemes, text):
		self.schemes = schemes
		self.id = None
		self.name = None
		self.class_name = None
		self.vars = None
		self.parse(text)
	#end define
	
	def __str__(self):
		result = f"<TlScheme {self.name}>"
		return result
	#end define
	
	def __repr__(self):
		return self.__str__()
	#end define
	
	def parse(self, text):
		end = ';'
		if end in text:
			text = text.replace(end, '')
		#end if
		
		sep = '='
		if sep not in text:
			return
		buff = text.split(' ')
		self.id = CRC32(text)
		self.name = buff.pop(0)
		self.class_name = buff.pop(-1)
		buff.remove(sep)
		vars = dict()
		for item in buff.copy():
			sep = ':'
			if sep not in item:
				continue
			buff = item.split(sep)
			var_name = buff.pop(0)
			var_type = buff.pop()
			vars[var_name] = var_type
		self.vars = vars
	#end define
	
	def load_bytes(self, byte_stream, alen=4):
		buff = byte_stream.read(1)
		if buff == bytes.fromhex("fe"):
			buff = byte_stream.read(3)
		dlen = int.from_bytes(buff, byteorder="little")
		rdata = byte_stream.read(dlen)
		
		if dlen % alen != 0:
			nlen = alen - dlen % alen
			null = byte_stream.read(nlen)
		return rdata
	#end define
	
	def deserialize(self, data):
		if type(data) == ByteStream:
			byte_stream = data
		elif type(data) == bytes:
			byte_stream = ByteStream(data)
		else:
			raise Exception("Tl deserialize error: Input parameter type must be ByteStream")
		#end if
		
		result = Dict()
		for var_name, var_type in self.vars.items():
			if var_type == "int":
				buff = byte_stream.read(4)
				var_value = Int(buff)
			elif var_type == "long":
				buff = byte_stream.read(8)
				var_value = Int(buff)
			elif var_type == "int256":
				buff = byte_stream.read(32)
				var_value = buff.hex()
			elif var_type == "bytes":
				var_value = self.load_bytes(byte_stream)
			else:
				scheme = self.schemes.get_scheme_by_name(var_type)
				var_value = scheme.deserialize(byte_stream)
			result[var_name] = var_value
		result.to_class()
		return result
	#end define
	
	def serialize(self, **data):
		result = bytes()
		for var_name, var_type in self.vars.items():
			var_value = data.get(var_name)
			if var_value == None:
				raise Exception(f"Serialize error: '{var_name}' not found in input parameters.")
			if var_type == "int":
				result += Int2Bytes(var_value)
			elif var_type == "long":
				result += Long2Bytes(var_value)
			elif var_type == "int256":
				result += bytes.fromhex(var_value)
			else:
				scheme = self.schemes.get_scheme_by_name(var_type)
				result += scheme.serialize(**var_value)
		return result
	#end define
#end class

def TlLen(data):
	dlen = len(data)
	if dlen < 254:
		dlen = dlen.to_bytes(1, byteorder="little")
	else:
		buff = bytes.fromhex("fe")
		dlen = buff + dlen.to_bytes(3, byteorder="little")
	return dlen
#end define

def CRC32(text):
	buff = binascii.crc32(text.encode("utf8"))
	result = int.to_bytes(buff, length=4, byteorder="little")
	return result
#end define

def Int(data):
	return int.from_bytes(data, byteorder="little", signed=True)
#end define

def Int2Bytes(data):
	return int.to_bytes(data, length=4, byteorder="little", signed=True)
#end define

def Long2Bytes(data):
	return int.to_bytes(data, length=8, byteorder="little", signed=True)
#end define

