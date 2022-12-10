#!/usr/bin/env python3
# -*- coding: utf_8 -*-

import os
import math
import json
from bitstring import BitStream # pip3 install bitstring
from mytypes import Cell, Slice, Dict, cell2dict


class TlbSchemes:
	def __init__(self):
		self.schemes = list()
		self.buff_result = None
		self.using_scheme = None
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
			#print(f"TlbScheme: {scheme}")
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
		self.using_scheme = scheme
		result = self.deser_vars(slice, scheme.vars)
		result["@name"] = scheme.name
		return result
	#end define
	
	def deser_vars(self, slice, vars):
		result = Dict()
		self.buff_result = result
		for var_name, var_type in vars.items():
			var_value = self.deser_types(slice, var_type)
			result[var_name] = var_value
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
		elif var_type == "#":
			buff = bit_stream.read(32)
			var_value = buff.uint
		elif var_type == "##":
			l = self.get_subvar(subvars[0])
			buff = bit_stream.read(l)
			var_value = buff.uint
		elif var_type == "#<=":
			l = self.get_receptacle(subvars[0])
			buff = bit_stream.read(l)
			var_value = buff.uint
		elif var_type == "bits":
			l = self.get_subvar(subvars[0])
			buff = bit_stream.read(l)
			var_value = buff.hex
		elif var_type == "HashmapE":
			var_value = self.deser_hashmap_e(slice, subvars[0], subvars[1])
		elif var_type == "HashmapAugE":
			var_value = self.deser_hashmap_aug_e(slice, subvars[0], subvars[1])
		elif var_type.startswith('^'):
			var_value = self.deser_cell(slice, var_type)
		else:
			var_value = self.deserialize(slice, var_type)
		return var_value
	#end define
	
	def get_receptacle(self, m):
		# (#<= m)
		a1 = self.get_subvar(m)
		a2 = "{0:b}".format(a1)
		n = len(a2)
		#n2 = int(math.ceil(math.log2(m + 1))) # n == n2
		return n
	#end define
	
	def deser_step2(self, var_type, slice):
		bit_stream = slice.bit_stream
		var_type = var_type[1:-1]
		subvars = split_string(var_type)
		subvar_type = subvars.pop(0)
		var_value = self.deser_types(slice, subvar_type, subvars)
		return var_value
	#end define
	
	def get_subvar(self, subvar):
		if type(subvar) == int:
			l = subvar
		elif subvar.isalnum():
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
	
	def deser_hashmap_e(self, slice, n, xtype):
		s = ""
		n = int(n)
		result = dict()
		print(f"deser_hashmap_e: {n} {xtype}")
		bit_stream = slice.bit_stream
		buff = bit_stream.read(1)
		if buff.bin == '0':
			# hme_empty
			return
		# hme_root
		cell = slice.read_ref()
		new_slice = Slice(cell)
		self.deser_hashmap(result, new_slice, n, s, xtype)
		print(f"deser_hashmap_e: {result}")
		return result
	#end define
	
	def deser_hashmap(self, result, slice, n, s, xtype):
		# hm_edge
		l, s2 = self.deser_hm_label(slice, n, s)
		m = n - l
		self.deser_hashmap_node(result, slice, m, s2, xtype)
	#end define
	
	def deser_hm_label(self, slice, m, s):
		bit_stream = slice.bit_stream
		buff = bit_stream.read(1)
		if buff.bin == '0':
			# hml_short
			print("hml_short")
			n = self.deser_unary(bit_stream)
			s2 = ""
		else:
			buff += bit_stream.read(1)
		if buff.bin == '10':
			# hml_long
			print("hml_long")
			l = self.get_receptacle(m)
			buff = bit_stream.read(l)
			n = buff.uint
			s2 = s + bit_stream.read(n)
		elif buff.bin == '11':
			# hml_same
			print("hml_same")
			buff = bit_stream.read(1)
			type_bit = buff.bin
			l = self.get_receptacle(m)
			buff = bit_stream.read(l)
			n = buff.uint
			s2 = type_bit * n
		return n, s2
	#end define
	
	def deser_unary(self, bit_stream):
		n = 0
		buff = bit_stream.read(1)
		while buff.bin == '1':
			n += 1
		return n
	#end define
	
	def deser_hashmap_node(self, result, slice, m, s, xtype):
		if m == 0:
			# hmn_leaf
			print(f"hmn_leaf: {xtype}")
			#bit_stream = slice.bit_stream
			#buff = bit_stream.read(bit_stream.len - bit_stream.pos)
			var_value = self.deser_types(slice, xtype)
			buff = BitStream(bin=s)
			var_key = buff.uint
			result[var_key] = var_value
			return
		#end if
		
		# hmn_fork
		n = m - 1
		
		# left
		print("left")
		s2 = s + '0'
		cell = slice.read_ref()
		new_slice = Slice(cell)
		self.deser_hashmap(new_slice, n, s2, xtype)
		
		# rigth
		print("rigth")
		s2 = s + '1'
		cell = slice.read_ref()
		new_slice = Slice(cell)
		self.deser_hashmap(new_slice, n, s2, xtype)
	#end define
	
	def deser_hashmap_aug_e(self, slice, subvar, subvar2):
		bit_stream = slice.bit_stream
		buff = bit_stream.read(1)
		if buff.bin == '0':
			return
		var_value = self.deser_hashmap_aug(bit_stream, subvar, subvar2)
		return var_value
	#end define
	
	def deser_cell(self, slice, var_type):
		var_type = var_type[1:]
		cell = slice.read_ref()
		new_slice = Slice(cell)
		if var_type == "Cell":
			var_value = cell2dict(cell, to_json=True)
		elif var_type.startswith('['):
			start = var_type.find('[') + 1
			end = var_type.find(']')
			vars_text = var_type[start:end]
			vars_buff = split_string(vars_text)
			vars = self.using_scheme.parse_vars(vars_buff)
			var_value = self.deser_vars(new_slice, vars)
		else:
			var_value = self.deser_types(new_slice, var_type)
		return var_value
	#end define
	
	def serialize(self, required, **data):
		cell = Cell()
		key, var_value = data.popitem()
		self.ser_types(cell, required, var_value)
		#scheme = self.get_schemes_by_name(required)[0]
		#print(f"required: {required}, scheme: {scheme}")
		#for var_name, var_type in scheme.vars.items():
			#var_value = data.get(var_name)
			#if var_value == None:
			#	raise Exception(f"TLB serialize error: '{var_name}' not found in input parameters.")
			#self.ser_types(cell, var_type, var_value)
		return cell
	#end define
	
	def ser_types(self, cell, var_type, var_value, subvars=None):
		if var_type == "int8":
			cell.data += int.to_bytes(var_value, length=1, byteorder="little", signed=True)
		elif var_type == "int32":
			cell.data += int.to_bytes(var_value, length=4, byteorder="little", signed=True)
		elif var_type == "uint32":
			cell.data += int.to_bytes(var_value, length=4, byteorder="little", signed=False)
		elif var_type == "uint64":
			cell.data += int.to_bytes(var_value, length=8, byteorder="little", signed=False)
		elif var_type.startswith('('):
			cell.data += self.ser_step2(cell, var_type, var_value)
		elif var_type == "VmStack":
			new_cell = self.ser_vmstack(var_value)
			cell.copy(new_cell)
		else:
			cell.data += self.serialize(var_type, **var_value)
	#end define
	
	def ser_step2(self, cell, var_type, var_value):
		var_type = var_type[1:-1]
		subvars = split_string(var_type)
		subvar_type = subvars.pop(0)
		result = self.ser_types(cell, subvar_type, var_value, subvars)
		return result
	#end define
	
	def ser_vmstack(self, data):
		# ser_vmstack#_ depth:(## 24) stack:(VmStackList depth) = VmStack;
		if data is None:
			data = list()
		if type(data) != list:
			raise Exception("ser_vmstack error: input parameters must be 'list'")
		#end if
		
		cell = Cell()
		depth = len(data)
		for i in range(depth):
			item = data[i]
			if type(item) == int:
				# vm_stk_tinyint#01 value:int64 = VmStackValue;
				cell.data += bytes.fromhex("01")
				cell.data += int.to_bytes(item, length=8, byteorder="big", signed=True)
				cell.bits_sz += 1*8 + 8*8
			else:
				raise Exception(f"ser_vmstack error: TODO: '{type(item)}'")
			if i == 0:
				cell.add_ref(Cell())
			if i+1 < depth:
				new_cell = Cell()
				new_cell.add_ref(cell)
				cell = new_cell
			#end if
		#end for
		
		depth_bytes = int.to_bytes(depth, length=3, byteorder="big", signed=False)
		cell.data = depth_bytes + cell.data
		cell.bits_sz += 3*8
		return cell
	#end define
#end class

class TlbScheme:
	def __init__(self, text):
		self.name = None
		self.class_name = None
		self.vars = None
		self.prefix = None
		self.parse(text)
	#end define
	
	def __str__(self):
		result = f"<TlbScheme {self.name}={self.class_name}, {self.vars}>"
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
		if '{' in text or '}' in text:
			#print(f"Found a logical equation. Skipping: {text}")
			return
		#end if
		
		sep = " = "
		if sep not in text:
			return
		vars_buff = text.split(sep)
		self.class_name = vars_buff.pop(-1).strip()
		text = vars_buff.pop(0).strip()
		
		vars_buff = split_string(text)
		name_text = vars_buff.pop(0)
		#if name_text == '_':
		#	print(f"parse: TODO: link -> {name_text} -> {self.class_name}")
		#	print(f"vars_buff: {vars_buff}")
		#	return
		#if '#' in name_text:
		#	print(f"parse: TODO: # -> {name_text}")
		#	return
		if '$' in name_text:
			name_buff = name_text.split('$')
			self.name = name_buff.pop(0)
			self.prefix = name_buff.pop()
		self.vars = self.parse_vars(vars_buff)
	#end define
	
	def parse_vars(self, vars_buff):
		vars = dict()
		for item in vars_buff.copy():
			buff = item.split(':')
			if item.startswith('^'):
				var_name = "_subvars"
				var_type = item
			elif len(buff) == 1:
				var_name = "_"
				var_type = buff.pop()
			else:
				var_name = buff.pop(0)
				var_type = buff.pop()
			vars[var_name] = var_type
		return vars
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
		if letter in ['(', '{', '[']:
			bracket_index += 1
		elif letter in [')', '}', ']']:
			bracket_index -= 1
	if len(buff) > 0:
		buff = buff.strip()
		result.append(buff)
		buff = ""
	result = list(filter(None, result))
	return result
#end define
