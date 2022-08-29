#!/usr/bin/env python3
# -*- coding: utf_8 -*-

import os
import binascii
from bitstring import BitStream # pip3 install bitstring


class TlbSchemes:
	def __init__(self):
		self.schemes = list()
		self.buff_result = None
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
			if line.startswith('//') or is_comment:
				continue
			if ';' in line:
				line = buff + line
				buff = ""
			else:
				buff += line
			scheme = TlbScheme(line)
			if scheme.name == None:
				continue
			self.schemes.append(scheme)
		#end for
	#end define
	
	def load_schemes_from_dir(self, dir):
		for file in os.listdir(dir):
			if file.endswith(".tlb"):
				filepath = dir + file
				self.load_schemes_from_file(filepath)
	#end define
	
	def get_schemes_by_name(self, name):
		result = list()
		for scheme in self.schemes:
			if scheme.class_name == name:
				result.append(scheme)
		if len(result) == 0:
			raise Exception(f"get_schemes_by_name error: scheme '{name}' not found")
		return result
	#end define
	
	def get_scheme_using_prefix(self, bit_stream, expected):
		schemes = self.get_schemes_by_name(expected)
		if len(schemes) == 1:
			return schemes[0]
		for scheme in schemes.copy():
			l = len(scheme.prefix)
			if scheme.prefix == bit_stream.bin[bit_stream.pos:bit_stream.pos+l]:
				bit_stream.read(l)
				return scheme
	#end define
	
	def deserialize(self, data, expected):
		if type(data) == BitStream:
			bit_stream = data
		if type(data) == bytes:
			bit_stream = BitStream(data)
		elif type(data) != BitStream:
			raise Exception("Deserialize error: Input parameter type must be BitStream")
		#end if
		
		scheme = self.get_scheme_using_prefix(bit_stream, expected)
		print(f"deserialize: scheme: {scheme.name}")
		result = Dict()
		self.buff_result = result
		for var_name, var_type in scheme.vars.items():
			if var_type == "int8":
				buff = bit_stream.read(8)
				var_value = buff.int
			elif var_type == "int32":
				buff = bit_stream.read(32)
				var_value = buff.int
			elif var_type == "uint32":
				buff = bit_stream.read(32)
				var_value = buff.uint
			elif var_type == "uint64":
				buff = bit_stream.read(64)
				var_value = buff.uint
			elif var_type == "bits256":
				buff = bit_stream.read(256)
				var_value = buff.hex
			elif var_type.startswith('('):
				var_value = self.deser_step2(var_type, bit_stream)
				if var_value == "break":
					break
			else:
				var_value = self.deserialize(bit_stream, var_type)
			result[var_name] = var_value
			print(f"buff_result: {self.buff_result}")
		result.toClass()
		return result
	#end define
	
	def deser_step2(self, var_type, bit_stream):
		var_type = var_type[1:-1]
		subvars = SplitString(var_type)
		subvar_type = subvars.pop(0)
		subvar = subvars.pop(0)
		if subvar_type == "Maybe":
			var_value = self.deser_maybe(bit_stream, subvar)
		elif subvar_type == "VarUInteger":
			var_value = self.deser_var_uinteger(bit_stream, subvar)
		elif subvar_type == "##":
			l = self.get_subvar(subvar)
			buff = bit_stream.read(l)
			var_value = buff.uint
		elif subvar_type == "bits":
			l = self.get_subvar(subvar)
			buff = bit_stream.read(l)
			var_value = buff.hex
		#elif subvar_type == "HashmapE":
		#	l = self.get_subvar(subvar)
		#	buff = bit_stream.read(l)
		#	var_value = buff.hex
		else:
			var_value = "break"
			print(f"deser_step2: TODO: {var_type}")
		return var_value
	#end define
	
	def get_subvar(self, subvar):
		if subvar.isalnum():
			l = int(subvar)
		else:
			l = self.buff_result.get(subvar)
		return l
	#end define
	
	def deser_var_uinteger(self, bit_stream, subvar):
		l = self.get_subvar(subvar)
		a = "{0:b}".format(l-1)
		l = len(a)
		buff = bit_stream.read(l)
		if buff.uint == 0:
			return 0
		b = buff.uint * 8
		buff = bit_stream.read(b)
		return buff.uint
	#end define
	
	def deser_maybe(self, bit_stream, subvar):
		buff = bit_stream.read(1)
		if buff.bin == '0':
			return
		var_value = self.deserialize(bit_stream, subvar)
		return var_value
	#end define
#end class

class TlbScheme:
	def __init__(self, text):
		self.name = None
		self.class_name = None
		self.vars = None
		self.prefix = None
		self.Parse(text)
	#end define
	
	def __str__(self):
		result = f"<TlbScheme {self.name}={self.class_name}>"
		return result
	#end define
	
	def __repr__(self):
		return self.__str__()
	#end define
	
	def Parse(self, text):
		end = ';'
		if end in text:
			text = text.replace(end, '')
		if '{' in text or '}' in text:
			#print("Found a logical equation. Skipping")
			return
		#end if
		
		sep = " = "
		if sep not in text:
			return
		buff = text.split(sep)
		self.class_name = buff.pop(-1).strip()
		text = buff.pop(0).strip()
		
		
		buff = SplitString(text)
		name_text = buff.pop(0)
		if name_text == '_':
			#print("Parse: TODO: link")
			return
		if '#' in name_text:
			#print("Parse: TODO: #")
			return
		if '$' in name_text:
			name_buff = name_text.split('$')
			self.name = name_buff.pop(0)
			self.prefix = name_buff.pop()
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
#end class

def SplitString(text, sep=' '):
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

class Dict(dict):
	def toClass(self):
		for key, value in self.items():
			setattr(self, key, value)
		#end for
	#end define
#end class





tlb_schemes = TlbSchemes()
tlb_schemes.load_schemes("/usr/src/ton/crypto/block/block.tlb")

cell_data = bytes.fromhex("c0021137b0bc47669b3267f1de70cbb0cef5c728b8d8c7890451e8613b2d899827026a886043179d3f6000006e233be8722201d7d239dba7d8181340")

data = tlb_schemes.deserialize(cell_data, "Account")
print(f"data: {data}")