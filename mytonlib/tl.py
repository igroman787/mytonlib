#!/usr/bin/env python3
# -*- coding: utf_8 -*-

import os
import fastcrc
from bitstring import BitArray
from io import BytesIO as ByteStream
from .mytypes import Dict


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
		is_comment = False
		buff = ""
		for line in lines:
			if "/*" in line:
				is_comment = True
				continue
			elif "*/" in line:
				is_comment = False
				continue
			if line.startswith('//') or line.startswith('---') or is_comment:
				continue
			#end if
			
			buff += line
			if ';' in line:
				scheme = TlScheme(self, buff)
				buff = ""
			else:
				continue
			if scheme.name == None:
				continue
			self.schemes_names[scheme.name] = scheme
			self.schemes_ids[scheme.id] = scheme.name
			#print(f"tl scheme: {scheme.name}, {scheme.class_name}")
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
			raise Exception(f"get_scheme_by_name error: TL scheme '{scheme_name}' not found")
		return result
	#end define
	
	def get_scheme_by_class_name(self, scheme_class_name, scheme_id):
		for scheme_name, scheme in self.schemes_names.items():
			if scheme_class_name == scheme.class_name and scheme.id == scheme_id:
				return scheme
		raise Exception(f"get_scheme_by_class_name error: TL scheme '{scheme_class_name}' not found")
	#end define
	
	def get_scheme_by_id(self, id):
		scheme_name = self.schemes_ids.get(id)
		result = self.schemes_names.get(scheme_name)
		if result is None:
			raise Exception(f"get_scheme_by_id error: TL scheme '{id.hex()}' not found")
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
		self.buff_result = None
		self.parse(text)
	#end define
	
	def __str__(self):
		result = f"<TlScheme {self.name}#{self.id.hex()}>"
		return result
	#end define
	
	def __repr__(self):
		return self.__str__()
	#end define
	
	def parse(self, text):
		end = ';'
		if end in text:
			endp = text.find(end)
			text = text[:endp]
		#end if
		
		# remove extra spaces
		text = " ".join(text.split())
		
		sep = '='
		if sep not in text:
			return
		buff = split_string(text)
		self.id = crc32(text)
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
	
	def deserialize(self, data, **send_data):
		if type(data) == ByteStream:
			byte_stream = data
		elif type(data) == bytes:
			byte_stream = ByteStream(data)
		else:
			raise Exception("Tl deserialize error: Input parameter type must be ByteStream")
		#end if
		
		result = Dict()
		self.buff_result = result
		for var_name, var_type in self.vars.items():
			result[var_name] = self.deser_types(byte_stream, var_type, send_data)
		result.to_class()
		result["@name"] = self.name
		return result
	#end define
	
	def deser_types(self, byte_stream, var_type, subvars=None):
		#p = byte_stream.tell()
		#buff = byte_stream.read()
		#byte_stream.seek(p)
		#print(f"deser_types: {var_type} -> {buff.hex()}")
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
			var_value = unpack_bytes(byte_stream)
		elif var_type == "string":
			buff = unpack_bytes(byte_stream)
			var_value = buff.decode("utf-8")
		elif var_type == "#":
			buff = byte_stream.read(4)
			var_value = Uint(buff)
		elif var_type.startswith('('):
			var_value = self.deser_step2(byte_stream, var_type)
		elif var_type == "vector":
			var_value = self.deser_vector(byte_stream, subvars[0])
		elif var_type.startswith("mode"):
			mode = self.buff_result.get("mode")
			var_value = self.deser_flags(byte_stream, var_type, mode)
		elif var_type.startswith("flags"):
			flags = self.buff_result.get("flags")
			var_value = self.deser_flags(byte_stream, var_type, flags)
		else:
			buff = var_type.split('.')[-1][0]
			if buff.isupper():
				# type is implicit
				scheme_id = byte_stream.read(4)
				scheme = self.schemes.get_scheme_by_id(scheme_id)
				var_value = scheme.deserialize(byte_stream)
			else:
				# the type is specified explicitly
				scheme = self.schemes.get_scheme_by_name(var_type)
				var_value = scheme.deserialize(byte_stream)
		return var_value
	#end define
	
	def deser_step2(self, byte_stream, var_type):
		var_type = var_type[1:-1]
		subvars = split_string(var_type)
		subvar_type = subvars.pop(0)
		#print(f"deser_step2: {subvar_type}, {subvars}")
		var_value = self.deser_types(byte_stream, subvar_type, subvars)
		return var_value
	#end define
	
	def deser_vector(self, byte_stream, var_type):
		#print(f"deser_vector: {var_type}")
		result = list()
		buff = byte_stream.read(4)
		dlen = Uint(buff)
		for i in range(dlen):
			var_value = self.deser_types(byte_stream, var_type)
			result.append(var_value)
		return result
	#end define
	
	def deser_flags(self, byte_stream, var_type, flags):
		var_in_flags, var_type = self.is_var_in_flags(var_type, flags)
		if var_in_flags == True:
			var_value = self.deser_types(byte_stream, var_type)
			return var_value
	#end define
	
	def serialize(self, **data):
		result = bytes()
		flags = data.get("flags")
		mode = data.get("mode")
		for var_name, var_type in self.vars.items():
			if var_name == "from":
				var_name = "_from"
			if "flags." in var_type:
				var_in_flags, var_type = self.is_var_in_flags(var_type, flags)
				if var_in_flags == False:
					continue
			if "mode." in var_type:
				var_in_flags, var_type = self.is_var_in_flags(var_type, mode)
				if var_in_flags == False:
					continue
			var_value = data.get(var_name)
			if var_value == None:
				raise Exception(f"TL serialize error: '{var_name}' not found in input parameters.")
			buff = self.ser_types(var_type, var_value)
			result += buff
		return result
	#end define
	
	def ser_types(self, var_type, var_value, subvars=None):
		#print(f"ser_types: {var_type}, <- {var_value}")
		if var_type == "int":
			result = int.to_bytes(var_value, length=4, byteorder="little", signed=True)
		elif var_type == "long":
			result = int.to_bytes(var_value, length=8, byteorder="little", signed=True)
		elif var_type == "int256":
			result = bytes.fromhex(var_value)
		elif var_type == "bytes":
			result = pack_bytes(var_value)
		elif var_type == "#":
			result = int.to_bytes(var_value, length=4, byteorder="little", signed=False)
		elif var_type.startswith('('):
			result = self.ser_step2(var_type, var_value)
		elif var_type == "vector":
			result = self.ser_vector(subvars[0], var_value)
		else:
			buff = var_type.split('.')[-1][0]
			if buff.isupper():
				# type is implicit
				scheme_name = var_value.get("scheme_name")
				scheme = self.schemes.get_scheme_by_name(scheme_name)
				result = scheme.id + scheme.serialize(**var_value)
			else:
				# the type is specified explicitly
				scheme = self.schemes.get_scheme_by_name(var_type)
				result = scheme.serialize(**var_value)
		return result
	#end define
	
	def ser_step2(self, var_type, var_value):
		var_type = var_type[1:-1]
		subvars = split_string(var_type)
		subvar_type = subvars.pop(0)
		result = self.ser_types(subvar_type, var_value, subvars)
		return result
	#end define
	
	def ser_vector(self, var_type, var_value):
		if type(var_value) is not list:
			raise Exception(f"TL serialize error: input parameter must be a 'list'.")
		dlen = len(var_value)
		result = int.to_bytes(dlen, length=4, byteorder="little", signed=False)
		for item in var_value:
			result += self.ser_types(var_type, item)
		return result
	#end define
	
	def is_var_in_flags(self, var_type, flags_int):
		buff = var_type.split('?')
		flag_str = buff[0]
		var_type = buff[1]
		flag_int = self.parse_flags_str(flag_str)
		flags_int_list = self.deser_flags_int(flags_int)
		var_in_flags = False
		if flag_int in flags_int_list:
			var_in_flags = True
		return var_in_flags, var_type
	#end define
	
	def parse_flags_str(self, flags_str):
		sep = ' '
		mode_len = 32
		result = list()
		flags_str = flags_str.replace('.', sep)
		flags_str = flags_str.replace(',', sep)
		flags_str = flags_str.split(sep)
		for item in flags_str:
			if item.isdigit():
				result.append(int(item))
		if len(result) == 1:
			result = result[0]
		return result
	#end define
	
	def deser_flags_int(self, flags_int):
		flags_len = 32
		flags_int_list = list()
		flags_bytes = int.to_bytes(flags_int, length=4, byteorder="big")
		flags_bits = BitArray(flags_bytes)
		for i in range(flags_len):
			bit = flags_bits[i]
			index = flags_len - i - 1
			if bit == True:
				flags_int_list.append(index)
		return flags_int_list
	#end define
#end class

def split_string(text, sep=' '):
	buff = ""
	result = list()
	bracket_index = 0
	for letter in text:
		if letter == sep and bracket_index == 0:
			buff = buff.strip()
			result.append(buff)
			buff = ""
		else:
			buff += letter
		if letter in ['(', '{']:
			bracket_index += 1
		elif letter in [')', '}']:
			bracket_index -= 1
	if len(buff) > 0:
		buff = buff.strip()
		result.append(buff)
		buff = ""
	result = list(filter(None, result))
	return result
#end define

def tl_len(data):
	data_len = len(data)
	if data_len < 254:
		data_len_bytes = data_len.to_bytes(1, byteorder="little")
	else:
		buff = bytes.fromhex("fe")
		data_len_bytes = buff + data_len.to_bytes(3, byteorder="little")
	return data_len_bytes
#end define

def align_bytes(data, align_len=4):
	data_len = len(data)
	null_len = 0
	blen = data_len % align_len
	if blen != 0:
		null_len = align_len - blen
	buff = bytes.fromhex("00")
	result = data + buff * null_len
	return result
#end define

def pack_bytes(data):
	data_len_bytes = tl_len(data)
	data = align_bytes(data_len_bytes + data)
	return data
#end define

def unpack_bytes(byte_stream, alen=4):
	attach_len = 1
	buff = byte_stream.read(1)
	if buff == bytes.fromhex("fe"):
		buff = byte_stream.read(3)
		attach_len = 4
	data_len = int.from_bytes(buff, byteorder="little")
	rdata = byte_stream.read(data_len)
	blen = (data_len + attach_len) % alen
	if blen != 0:
		null_len = alen - blen
		null = byte_stream.read(null_len)
	#print(f"unpack_bytes: {data_len}, {rdata.hex()}")
	#print(f"unpack_bytes null: {null_len}, {null.hex()}")
	return rdata
#end define

def crc32(text):
	text = text.replace('(', '')
	text = text.replace(')', '')
	buff = fastcrc.crc32.iso_hdlc(text.encode("utf8"))
	result = int.to_bytes(buff, length=4, byteorder="little")
	return result
#end define

def Int(data):
	return int.from_bytes(data, byteorder="little", signed=True)
#end define

def Uint(data):
	return int.from_bytes(data, byteorder="little", signed=False)
#end define

