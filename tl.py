#!/usr/bin/env python3
# -*- coding: utf_8 -*-

import os
#import binascii
import fastcrc
from bitstring import BitArray
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
	
	def get_scheme_by_class_name(self, scheme_class_name, var_value):
		for scheme_name, scheme in self.schemes_names.items():
			if scheme_class_name == scheme.class_name and scheme.id == var_value[:4]:
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
	
	def deserialize(self, data, **send_data):
		if type(data) == ByteStream:
			byte_stream = data
		elif type(data) == bytes:
			byte_stream = ByteStream(data)
		else:
			raise Exception("Tl deserialize error: Input parameter type must be ByteStream")
		#end if
		
		result = Dict()
		for var_name, var_type in self.vars.items():
			result[var_name] = self.deser_types(byte_stream, var_type, send_data)
		result.to_class()
		return result
	#end define
	
	def deser_types(self, byte_stream, var_type, send_data=None, subvars=None):
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
		elif var_type == "string":
			buff = byte_stream.read()
			var_value = buff.decode("utf-8")
		elif var_type == "#":
			buff = byte_stream.read(4)
			var_value = Uint(buff)
		elif var_type.startswith("mode"):
			var_value = self.deser_mode(byte_stream, var_type, send_data)
		else:
			scheme = self.schemes.get_scheme_by_name(var_type)
			var_value = scheme.deserialize(byte_stream)
		return var_value
	#end define
	
	def deser_mode(self, byte_stream, var_type, send_data):
		send_mode = send_data.get("mode")
		buff = var_type.split('?')
		modes = buff[0]
		var_type = buff[1]
		modes = modes.split('.')
		mode = modes[-1]
		buff = self.check_mode(mode, send_mode)
		if buff is True:
			var_value = self.deser_types(byte_stream, var_type)
			return var_value
	#end define
	
	def check_mode(self, mode, send_mode):
		mode = int(mode)
		send_mode_bin = BitArray(f"uint:32={send_mode}")
		mode_len = len(send_mode_bin.bin)
		index = mode_len - mode - 1
		result = send_mode_bin.bin[index] == '1'
		return result
	#end define
	
	def serialize(self, **data):
		result = bytes()
		flags = data.get("flags")
		for var_name, var_type in self.vars.items():
			if var_name == "from":
				var_name = "_from"
			if "flags." in var_type:
				var_in_flags, var_type = self.is_var_in_flags(var_type, flags)
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
		if var_type == "int":
			result = int.to_bytes(var_value, length=4, byteorder="little", signed=True)
		elif var_type == "long":
			result = int.to_bytes(var_value, length=8, byteorder="little", signed=True)
		elif var_type == "int256":
			result = bytes.fromhex(var_value)
		elif var_type == "bytes":
			dlen = tl_len(var_value)
			result = align_bytes(dlen + var_value)
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
		result = int.to_bytes(dlen, length=4, byteorder="little", signed=True)
		for item in var_value:
			result += self.ser_types(var_type, item)
		return result
	#end define
	
	def is_var_in_flags(self, var_name, flags_int):
		buff = var_name.split('?')
		flag_str = buff[0]
		var_name = buff[1]
		flag_int = self.parse_flags_str(flag_str)
		flags_int_list = self.deser_flags(flags_int)
		var_in_flags = False
		if flag_int in flags_int_list:
			var_in_flags = True
		return var_in_flags, var_name
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
	
	def deser_flags(self, flags_int):
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
	dlen = len(data)
	if dlen < 254:
		dlen = dlen.to_bytes(1, byteorder="little")
	else:
		buff = bytes.fromhex("fe")
		dlen = buff + dlen.to_bytes(3, byteorder="little")
	return dlen
#end define

def align_bytes(data, alen=4):
	dlen = len(data)
	nlen = 0
	if dlen % alen != 0:
		nlen = alen - dlen % alen
	buff = bytes.fromhex("00")
	result = data + buff * nlen
	return result
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

