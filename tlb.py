#!/usr/bin/env python3
# -*- coding: utf_8 -*-

import os
from bitstring import BitStream # pip3 install bitstring
from mytypes import Cell, Slice, Dict, cell2dict


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
			#end if
			
			buff += line
			if ';' in line:
				scheme = TlbScheme(buff)
				buff = ""
			else:
				continue
			if scheme.class_name == None:
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
			raise Exception(f"get_schemes_by_name error: TLB scheme '{name}' not found")
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
	
	def deserialize(self, var, expected):
		if type(var) == Slice:
			slice = var
		elif type(var) == Cell:
			slice = Slice(var)
		else:
			raise Exception("Tlb deserialize error: Input parameter type must be Slice")
		#end if
		
		bit_stream = slice.bit_stream
		scheme = self.get_scheme_using_prefix(bit_stream, expected)
		#print(f"TlbSchemes deserialize: {expected} -> {scheme.name}, {scheme.class_name}, {scheme.vars}")
		result = Dict()
		result["@name"] = scheme.name
		self.buff_result = result
		for var_name, var_type in scheme.vars.items():
			var_value = self.deser_types(slice, var_type)
			result[var_name] = var_value
			#print(f"buff_result: {self.buff_result}")
		result.to_class()
		return result
	#end define
	
	def deser_types(self, slice, var_type, subvars=None):
		bit_stream = slice.bit_stream
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
			var_value = self.deser_step2(var_type, slice)
		elif var_type == "Maybe":
			var_value = self.deser_maybe(slice, subvars[0])
		elif var_type == "VarUInteger":
			var_value = self.deser_var_uinteger(bit_stream, subvars[0])
		elif var_type == "##":
			l = self.get_subvar(subvars[0])
			buff = bit_stream.read(l)
			var_value = buff.uint
		elif var_type == "bits":
			l = self.get_subvar(subvars[0])
			buff = bit_stream.read(l)
			var_value = buff.hex
		elif var_type == "HashmapE":
			var_value = self.deser_hashmapE(bit_stream, subvars[0], subvars[1])
		elif var_type == "^Cell":
			cell = slice.read_cell()
			var_value = cell2dict(cell, to_json=True)
		else:
			var_value = self.deserialize(slice, var_type)
		return var_value
	#end define
	
	def deser_step2(self, var_type, slice):
		bit_stream = slice.bit_stream
		var_type = var_type[1:-1]
		subvars = SplitString(var_type)
		subvar_type = subvars.pop(0)
		var_value = self.deser_types(slice, subvar_type, subvars)
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
	
	def deser_maybe(self, slice, subvar):
		bit_stream = slice.bit_stream
		buff = bit_stream.read(1)
		if buff.bin == '0':
			return
		var_value = self.deser_types(slice, subvar)
		return var_value
	#end define
	
	def deser_hashmapE(self, bit_stream, subvar, subvar2):
		buff = bit_stream.read(1)
		if buff.bin == '0':
			return
		var_value = self.deser_hashmap(bit_stream, subvar, subvar2)
		return var_value
	#end define
	
	def serialize(self, **data):
		result = bytes()
		for var_name, var_type in self.vars.items():
			var_value = data.get(var_name)
			if var_value == None:
				raise Exception(f"TLB serialize error: '{var_name}' not found in input parameters.")
			result += self.ser_types(var_value)
		return result
	#end define
	
	def ser_types(self, var_type, var_value, subvars=None):
		if var_type == "int8":
			result = int.to_bytes(var_value, length=1, byteorder="little", signed=True)
		elif var_type == "int32":
			result = int.to_bytes(var_value, length=4, byteorder="little", signed=True)
		elif var_type == "uint32":
			result = int.to_bytes(var_value, length=4, byteorder="little", signed=False)
		elif var_type == "uint64":
			result = int.to_bytes(var_value, length=8, byteorder="little", signed=False)
		elif var_type.startswith('('):
			result = self.ser_step2(var_type, var_value)
		else:
			scheme = self.schemes.get_scheme_by_name(var_type)
			result = scheme.serialize(**var_value)
		return result
	#end define
	
	def ser_step2(self, var_type, var_value):
		var_type = var_type[1:-1]
		subvars = SplitString(var_type)
		subvar_type = subvars.pop(0)
		result = self.ser_types(subvar_type, var_value, subvars)
		return result
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
		#if name_text == '_':
		#	print(f"Parse: TODO: link -> {name_text} -> {self.class_name}")
		#	print(f"buff: {buff}")
		#	return
		if '#' in name_text:
			print(f"Parse: TODO: # -> {name_text}")
			return
		if '$' in name_text:
			name_buff = name_text.split('$')
			self.name = name_buff.pop(0)
			self.prefix = name_buff.pop()
		vars = dict()
		for item in buff.copy():
			buff = item.split(':')
			if len(buff) == 1:
				var_name = "_"
			else:
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
