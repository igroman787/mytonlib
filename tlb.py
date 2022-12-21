#!/usr/bin/env python3
# -*- coding: utf_8 -*-

import os
import math
import json
from bitstring import BitStream # pip3 install bitstring
from mytypes import Cell, Slice, Dict, cell2dict, bits2hex


class TlbSchemes:
	def __init__(self):
		self.schemes = list()
		self.buff_result = None
		self.buff_subvars = dict()
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
	
	def get_schemes_by_class_name(self, name):
		result = list()
		for scheme in self.schemes:
			if scheme.class_name == name:
				result.append(scheme)
		if len(result) == 0:
			raise Exception(f"get_schemes_by_class_name error: TLB scheme '{name}' not found")
		return result
	#end define
	
	def get_scheme_using_prefix(self, slice, expected):
		bit_stream = slice.bit_stream
		schemes = self.get_schemes_by_class_name(expected)
		#if len(schemes) == 1:
		#	scheme = schemes[0]
		#	if scheme.prefix_bit != None:
		#		bit_len = len(scheme.prefix_bit)
		#		buff = bit_stream.read(bit_len)
		#	return scheme
		for scheme in schemes.copy():
			print(f"get_scheme_using_prefix scheme: {scheme}")
			bit_len = scheme.get_prefix_bit_len()
			prefix_bit = bit_stream.bin[bit_stream.pos:bit_stream.pos+bit_len]
			if scheme.prefix_bit == prefix_bit or bit_len == 0:
				bit_stream.read(bit_len)
				return scheme
			#end if
		raise Exception(f"get_scheme_using_prefix error: TLB scheme '{expected}' with prefix '{prefix_bit}' not found")
	#end define
	
	def deserialize(self, var, expected, old_subvars=None):
		if type(var) == Slice:
			slice = var
		elif type(var) == Cell:
			slice = Slice(var)
		else:
			raise Exception("Tlb deserialize error: Input parameter type must be Slice")
		#end if
		
		scheme = self.get_scheme_using_prefix(slice, expected)
		#print(f"TlbSchemes deserialize: {expected} -> {scheme.name}, {scheme.class_name}, {scheme.vars}")
		self.save_class_vars(scheme, old_subvars)
		if scheme.is_link == True:
			result = self.deser_types(slice, scheme.link)
		else:
			result = self.deser_vars(slice, scheme.vars)
			result["@name"] = scheme.name
		return result
	#end define
	
	def save_class_vars(self, scheme, old_subvars):
		self.using_scheme = scheme
		if scheme.class_vars == None:
			return
		#print(f"save_class_vars: {scheme.name} -> {scheme.class_vars}, old_subvars={old_subvars}")
		for item in scheme.class_vars:
			self.buff_subvars[item] = old_subvars.pop(0)
	#end define
	
	def deser_vars(self, slice, vars):
		result = Dict()
		self.buff_result = result
		for var_name, var_type in vars.items():
			var_value = self.deser_types(slice, var_type)
			if var_name == "_subvars_":
				result.update(var_value)
			else:
				result[var_name] = var_value
		result.to_class()
		return result
	#end define
	
	def deser_types(self, slice, var_type, subvars=None):
		#print(f"deser_types: {var_type}, subvars={subvars}")
		bit_stream = slice.bit_stream
		if var_type.startswith("int"):
			var_value = self.deser_var_int(bit_stream, var_type)
		elif var_type.startswith("uint"):
			var_value = self.deser_var_uint(bit_stream, var_type)
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
		elif var_type == "Bool":
			var_value = self.deser_bool(slice)
		elif var_type == "Either":
			var_value = self.deser_either(slice, subvars[0], subvars[1])
		elif var_type == "BinTree":
			var_value = self.deser_bin_tree(slice, subvars[0])
		elif var_type == "HashmapE":
			var_value = self.deser_hashmap_e(slice, subvars[0], subvars[1])
		elif var_type == "HashmapAugE":
			var_value = self.deser_hashmap_aug_e(slice, subvars[0], subvars[1])
		elif var_type.startswith('^'):
			var_value = self.deser_ref(slice, var_type)
		elif var_type in ["Any", "Cell"]:
			var_value = self.deser_cell(slice)
		elif var_type in self.buff_subvars:
			x_type = self.buff_subvars.get(var_type)
			var_value = self.deser_types(slice, x_type)
		else:
			var_value = self.deserialize(slice, var_type, subvars)
		return var_value
	#end define
	
	def deser_var_int(self, bit_stream, var_type):
		int_len = int(var_type[3:])
		buff = bit_stream.read(int_len)
		return buff.int
	#end define
	
	def deser_var_uint(self, bit_stream, var_type):
		int_len = int(var_type[4:])
		buff = bit_stream.read(int_len)
		return buff.uint
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
	
	def deser_maybe(self, slice, x_type):
		bit_stream = slice.bit_stream
		buff = bit_stream.read(1)
		if buff.bin == '0':
			return
		var_value = self.deser_types(slice, x_type)
		return var_value
	#end define
	
	def deser_bool(self, slice):
		bit_stream = slice.bit_stream
		buff = bit_stream.read(1)
		if buff.bin == '1':
			return True
		return False
	#end define
	
	def deser_either(self, slice, x_type, y_type):
		bit_stream = slice.bit_stream
		buff = bit_stream.read(1)
		if buff.bin == '0':
			var_value = self.deser_types(slice, x_type)
		else:
			var_value = self.deser_types(slice, y_type)
		return var_value
	#end define
	
	def deser_bin_tree(self, slice, x_type):
		bit_stream = slice.bit_stream
		buff = bit_stream.read(1)
		if buff.bin == '0':
			result = self.deser_types(slice, x_type)
		elif buff.bin == '1':
			result = dict()
			left_cell = slice.read_ref()
			left_slice = Slice(left_cell)
			result["left"] = self.deser_bin_tree(left_slice, x_type)
			right_cell = slice.read_ref()
			right_slice = Slice(right_cell)
			result["right"] = self.deser_bin_tree(right_slice, x_type)
		return result
	#end define
	
	def deser_hashmap_e(self, slice, n, x_type):
		s = ""
		n = int(n)
		result = dict()
		#print(f"deser_hashmap_e: {n} {x_type}")
		bit_stream = slice.bit_stream
		buff = bit_stream.read(1)
		if buff.bin == '0':
			# hme_empty
			return
		# hme_root
		cell = slice.read_ref()
		new_slice = Slice(cell)
		self.deser_hashmap(result, new_slice, n, s, x_type)
		#print(f"deser_hashmap_e: {result}")
		return result
	#end define
	
	def deser_hashmap(self, result, slice, n, s, x_type):
		# hm_edge
		l, s2 = self.deser_hm_label(slice, n, s)
		m = n - l
		self.deser_hashmap_node(result, slice, m, s2, x_type)
	#end define
	
	def deser_hm_label(self, slice, m, s):
		bit_stream = slice.bit_stream
		buff = bit_stream.read(1)
		if buff.bin == '0':
			# hml_short
			#print("hml_short")
			n = self.deser_unary(bit_stream)
			s2 = ""
		else:
			buff += bit_stream.read(1)
		if buff.bin == '10':
			# hml_long
			#print("hml_long")
			l = self.get_receptacle(m)
			buff = bit_stream.read(l)
			n = buff.uint
			s2 = s + bit_stream.read(n).bin
		elif buff.bin == '11':
			# hml_same
			#print("hml_same")
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
	
	def deser_hashmap_node(self, result, slice, m, s, x_type):
		if m == 0:
			# hmn_leaf
			#print(f"hmn_leaf: {x_type}")
			var_value = self.deser_types(slice, x_type)
			buff = BitStream(bin=s)
			var_key = buff.uint
			result[var_key] = var_value
			return
		#end if
		
		# hmn_fork
		n = m - 1
		
		# left
		#print("left")
		s2 = s + '0'
		cell = slice.read_ref()
		new_slice = Slice(cell)
		self.deser_hashmap(result, new_slice, n, s2, x_type)
		
		# rigth
		#print("rigth")
		s2 = s + '1'
		cell = slice.read_ref()
		new_slice = Slice(cell)
		self.deser_hashmap(result, new_slice, n, s2, x_type)
	#end define
	
	def deser_hashmap_aug_e(self, slice, subvar, subvar2):
		bit_stream = slice.bit_stream
		buff = bit_stream.read(1)
		if buff.bin == '0':
			return
		var_value = self.deser_hashmap_aug(bit_stream, subvar, subvar2)
		return var_value
	#end define
	
	def deser_ref(self, slice, var_type):
		var_type = var_type[1:]
		new_cell = slice.read_ref()
		new_slice = Slice(new_cell)
		if var_type.startswith('['):
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
	
	def deser_cell(self, slice):
		bit_stream = slice.bit_stream
		data_len = bit_stream.len - bit_stream.pos
		data = bits2hex(bit_stream.read(data_len))
		start = slice.refs_pos
		end = len(slice.refs)
		for i in range(start, end):
			new_cell = slice.refs[i]
			new_slice = Slice(new_cell)
			data += self.deser_cell(new_slice)
		return data
	#end define
	
	def serialize(self, required, **data):
		cell = Cell()
		key, var_value = data.popitem()
		self.ser_types(cell, required, var_value)
		#scheme = self.get_schemes_by_class_name(required)[0]
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
		self.class_vars = None
		self.vars = None
		self.prefix_bit = None
		self.is_link = False
		self.parse(text)
	#end define
	
	def __str__(self):
		result = f"<TlbScheme name={self.name}, class_name={self.class_name}, prefix_bit={self.prefix_bit} vars={self.vars}, class_vars={self.class_vars}>"
		return result
	#end define
	
	def __repr__(self):
		return self.__str__()
	#end define
	
	def get_prefix_bit_len(self):
		prefix_bit_len = 0
		if self.prefix_bit != None:
			prefix_bit_len = len(self.prefix_bit)
		return prefix_bit_len
	#end define
	
	def parse(self, text):
		end = ';'
		if end in text:
			endp = text.find(end)
			text = text[:endp]
		#end if
		
		sep = "="
		if sep not in text:
			return
		#end if
		
		sep_pos = text.rfind(sep)
		class_text = text[sep_pos+1:].strip()
		vars_text = text[:sep_pos].strip()
		
		class_buff = class_text.split()
		self.class_name = class_buff.pop(0)
		if len(class_buff) > 0:
			self.class_vars = class_buff
		#end if
		
		vars_buff = split_string(vars_text)
		name_text = vars_buff.pop(0)
		if '$' in name_text:
			name_buff = name_text.split('$')
			self.name = name_buff.pop(0)
			prefix_bit = name_buff.pop()
			prefix_bit = prefix_bit.replace('_', '')
			if prefix_bit != '':
				self.prefix_bit = prefix_bit
		elif '#' in name_text:
			name_buff = name_text.split('#')
			self.name = name_buff.pop(0)
			prefix_byte = name_buff.pop()
			prefix_byte = prefix_byte.replace('_', '')
			if prefix_byte != '':
				self.prefix_bit = BitStream(hex=prefix_byte).bin
			#end if
		if len(vars_buff) == 1 and ':' not in vars_buff[0]:
			#print(f"find link: vars_buff={vars_buff}, scheme={self}")
			self.is_link = True
			self.link = vars_buff.pop()
		else:
			#print(f"parse_vars: vars_buff={vars_buff}, scheme={self}")
			self.vars = self.parse_vars(vars_buff)
	#end define
	
	def parse_vars(self, vars_buff):
		vars = dict()
		for item in vars_buff.copy():
			if '{' in item or '}' in item:
				#print(f"Found a logical equation. Skipping: {item}")
				continue
			if ':' not in item:
				print(f"TLB schema syntax error found: {item}")
				continue
			buff = item.split(':')
			if item.startswith('^'):
				var_name = "_subvars_"
				var_type = item
			#elif len(buff) == 1:
			#	var_name = "_"
			#	var_type = buff.pop()
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
