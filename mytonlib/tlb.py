#!/usr/bin/env python3
# -*- coding: utf_8 -*-

import os
import math
import json
from bitstring import BitStream, BitArray # pip3 install bitstring
from .mytypes import Cell, Slice, Dict, bits2hex


class TlbSchemes:
	def __init__(self):
		self.schemes = list()
		self.buff_result = dict()
		self.buff_subvars = dict()
		self.using_scheme = None
	#end define
	
	def load_schemes(self, filepath):
		if os.path.isfile(filepath):
			self.load_schemes_from_file(filepath)
		elif os.path.isdir(filepath):
			self.load_schemes_from_dir(filepath)
		else:
			raise Exception(f"load_schemes error: `{filepath}` not found")
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
			if scheme in self.schemes:
				print(f"load_schemes_from_file warning: overwriting an existing tlb schema: {scheme.class_name}")
				self.schemes.remove(scheme)
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
	
	def get_schemes_by_class_name(self, class_name):
		class_vars = split_string(class_name)
		class_name = class_vars.pop(0)
		result = list()
		for scheme in self.schemes:
			if scheme.class_name == class_name:
				if len(class_vars) > 0 and scheme.class_vars == class_vars:
					result.append(scheme)
				elif len(class_vars) == 0:
					result.append(scheme)
			#if scheme.class_name == class_name and scheme.class_vars == class_vars:
			#	result.append(scheme)
		if len(result) == 0:
			raise Exception(f"get_schemes_by_class_name error: TLB scheme '{class_name}' not found")
		return result
	#end define
	
	def get_scheme_using_prefix(self, slice, expected):
		bit_stream = slice.bit_stream
		schemes = self.get_schemes_by_class_name(expected)
		for scheme in schemes.copy():
			#print(f"get_scheme_using_prefix scheme: {scheme}")
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
		elif var == None:
			return
		else:
			raise Exception(f"Tlb deserialize error: Input parameter type must be Cell or Slice. Find {type(var)}")
		#end if
		
		scheme = self.get_scheme_using_prefix(slice, expected)
		#print(f"TlbSchemes deserialize: {scheme}")
		self.save_class_vars(scheme, old_subvars)
		if scheme.is_link == True:
			result = self.deser_types(slice, scheme.link)
		else:
			result = self.deser_vars(slice, scheme.vars)
			result["@name"] = scheme.name
		return result
	#end define
	
	def save_class_vars(self, scheme, old_subvars):
		#print(f"save_class_vars: class_vars={scheme.class_vars}, old_subvars={old_subvars}")
		if old_subvars == None:
			old_subvars = list()
		self.using_scheme = scheme
		#if scheme.class_vars == None:
		#	return
		for item in scheme.class_vars:
			if item.isdigit() == False:
				self.buff_subvars[item] = old_subvars.pop(0)
	#end define
	
	def deser_vars(self, slice, vars):
		result = Dict()
		#self.buff_result = result
		for var_name, var_type in vars.items():
			var_value = self.deser_types(slice, var_type)
			if var_name == "_":
				result.update(var_value)
			else:
				result[var_name] = var_value
			self.buff_result.update(result)
		result.to_class()
		return result
	#end define
	
	def deser_types(self, slice, var_type, subvars=None):
		#print(f"deser_types: {var_type}, {slice}, subvars={subvars}")
		bit_stream = slice.bit_stream
		if var_type.startswith("int"):
			var_value = self.deser_var_int(bit_stream, var_type)
		elif var_type.startswith("uint"):
			var_value = self.deser_var_uint(bit_stream, var_type)
		elif var_type == "bits256":
			buff = bit_stream.read(256)
			var_value = buff.hex
		elif var_type.startswith('('):
			var_value = self.deser_step2(slice, var_type)
		elif '?' in var_type:
			var_value = self.deser_step3(slice, var_type)
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
		elif var_type == "Maybe":
			var_value = self.deser_maybe(slice, subvars[0])
		elif var_type == "VarUInteger":
			var_value = self.deser_var_uinteger(bit_stream, subvars[0])
		elif var_type == "Either":
			var_value = self.deser_either(slice, subvars[0], subvars[1])
		elif var_type == "BinTree":
			var_value = self.deser_bin_tree(slice, subvars[0])
		elif var_type == "Hashmap":
			var_value = dict()
			self.deser_hashmap(var_value, slice, int(subvars[0]), subvars[1])
		elif var_type == "HashmapE":
			var_value = self.deser_hashmap_e(slice, subvars[0], subvars[1])
		elif var_type == "HashmapAugE":
			var_value = self.deser_hashmap_aug_e(slice, subvars[0], subvars[1], subvars[2])
		elif var_type == "VmStackList":
			depth = self.get_subvar("depth")
			var_value = self.deser_vm_stack_list(slice, depth)
		elif slice.special == True:
			var_value = self.deser_special_cell(slice, var_type, subvars)
		elif var_type.startswith('^'):
			var_value = self.deser_ref(slice, var_type)
		elif var_type in ["Any", "Cell"]:
			var_value = slice.to_cell()
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
	
	def deser_step2(self, slice, var_type):
		var_type = var_type[1:-1]
		subvars = split_string(var_type)
		subvar_type = subvars.pop(0)
		var_value = self.deser_types(slice, subvar_type, subvars)
		return var_value
	#end define
	
	def deser_step3(self, slice, var_type):
		if var_type.startswith("flags"):
			var_value = self.deser_flags(slice, var_type)
		else:
			buff = var_type.split('?')
			suffix_var_name = buff[0]
			var_type = buff[1]
			suffix_var_value = self.buff_result.get(suffix_var_name)
			if suffix_var_value == True:
				var_value = self.deser_types(slice, var_type)
	#end define
	
	def get_subvar(self, subvar):
		if type(subvar) == int:
			l = subvar
		elif subvar.isdigit():
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
		#bit_stream = slice.bit_stream
		#buff = bit_stream.read(1)
		buff = slice.read_bits(1)
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
		#print(f"deser_hashmap_e buff: {buff.bin}")
		if buff.bin == '0':
			# hme_empty
			return
		# hme_root
		new_cell = slice.read_ref()
		new_slice = Slice(new_cell)
		self.deser_hashmap(result, new_slice, n, x_type, s)
		#print(f"deser_hashmap_e: {result}")
		return result
	#end define
	
	def deser_hashmap(self, result, slice, n, x_type, s=None):
		if s == None:
			s = ""
		if slice.special == True:
			return
		#print(f"deser_hashmap: {n}, {x_type}")
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
			n = self.deser_unary(bit_stream)
			s2 = s + bit_stream.read(n).bin
		else:
			buff += bit_stream.read(1)
		if buff.bin == '10':
			# hml_long
			l = self.get_receptacle(m)
			n = bit_stream.read(l).uint
			s2 = s + bit_stream.read(n).bin
		elif buff.bin == '11':
			# hml_same
			type_bit = bit_stream.read(1).bin
			l = self.get_receptacle(m)
			n = bit_stream.read(l).uint
			s2 = type_bit * n
		#print(f"deser_hm_label: m:{m}, n:{n}, s:`{s}` -> s2:`{s2}`")
		if n > m:
			raise Exception("HmLabel error: `n` must be <= `m`")
		return n, s2
	#end define
	
	def deser_unary(self, bit_stream):
		n = 0
		buff = bit_stream.read(1)
		while buff.bin == '1':
			n += 1
			buff = bit_stream.read(1)
		return n
	#end define
	
	def deser_hashmap_node(self, result, slice, m, s, x_type):
		if slice.special == True:
			return
		if m == 0:
			# hmn_leaf
			#print(f"hmn_leaf: {x_type}")
			var_value = self.deser_types(slice, x_type)
			buff = BitStream(bin=s)
			var_key = buff.uint
			result[var_key] = var_value
			#print(f"deser_hashmap_node {var_key} -> {var_value}")
			return
		#end if
		
		# hmn_fork
		n = m - 1
		
		# left
		#print("left")
		s2 = s + '0'
		new_cell = slice.read_ref()
		new_slice = Slice(new_cell)
		self.deser_hashmap(result, new_slice, n, x_type, s2)
		
		# rigth
		#print("rigth")
		s2 = s + '1'
		new_cell = slice.read_ref()
		new_slice = Slice(new_cell)
		self.deser_hashmap(result, new_slice, n, x_type, s2)
	#end define
	
	def deser_hashmap_aug_e(self, slice, n, x_type, y_type):
		#print(f"deser_hashmap_aug_e: {n}, {x_type}, {y_type}")
		s = ""
		n = int(n)
		result = dict()
		bit_stream = slice.bit_stream
		buff = bit_stream.read(1)
		#print(f"deser_hashmap_aug_e buff: {buff.bin}")
		if buff.bin == '0':
			# ahme_empty
			pass
		else:
			# ahme_root
			new_cell = slice.read_ref()
			new_slice = Slice(new_cell)
			self.deser_hashmap_aug(result, new_slice, n, s, x_type, y_type)
		var_extra = self.deser_types(slice, y_type)
		#print(f"deser_hashmap_aug_e var_value: {var_value}, var_extra: {var_extra}")
		return result
	#end define
	
	def deser_hashmap_aug(self, result, slice, n, s, x_type, y_type):
		if slice.special == True:
			return
		#print(f"deser_hashmap_aug: {n}, {x_type}, {y_type}")
		# ahm_edge
		l, s2 = self.deser_hm_label(slice, n, s)
		m = n - l
		self.deser_hashmap_aug_node(result, slice, m, s2, x_type, y_type)
	#end define
	
	def deser_hashmap_aug_node(self, result, slice, m, s, x_type, y_type):
		if slice.special == True:
			return
		#end if
		
		if m == 0:
			# ahmn_leaf
			#print(f"ahmn_leaf: {x_type}")
			var_extra = self.deser_types(slice, y_type)
			var_value = self.deser_types(slice, x_type)
			buff = BitStream(bin=s)
			var_key = buff.uint
			result[var_key] = var_value
			#print(f"deser_hashmap_aug_node {var_key} -> {var_value}")
			return
		#end if
		
		# ahmn_fork
		n = m - 1
		
		# left
		s2 = s + '0'
		new_cell = slice.read_ref()
		new_slice = Slice(new_cell)
		self.deser_hashmap_aug(result, new_slice, n, s2, x_type, y_type)
		
		# rigth
		s2 = s + '1'
		new_cell = slice.read_ref()
		new_slice = Slice(new_cell)
		self.deser_hashmap_aug(result, new_slice, n, s2, x_type, y_type)
		
		var_extra = self.deser_types(slice, y_type)
	#end define
	
	def deser_vm_stack(self, slice):
		bit_stream = slice.bit_stream
		buff = bit_stream.read(24)
		depth = buff.uint
		stack = self.deser_vm_stack_list(slice, depth)
		return stack
	#end define
	
	def deser_vm_stack_list(self, slice, depth):
		if slice.special == True:
			return self.deser_special_cell(slice)
		if depth == 0:
			return
		#print(f"deser_vm_stack_list: depth={depth}")
		new_cell = slice.read_ref()
		new_slice = Slice(new_cell)
		stack = Dict()
		stack["rest"] = self.deser_vm_stack_list(new_slice, depth-1)
		stack["tos"] = self.deser_types(slice, "VmStackValue")
		stack.to_class()
		return stack
	#end define
	
	def deser_ref(self, slice, var_type):
		if slice.special == True:
			return self.deser_special_cell(slice, var_type)
		var_type = var_type[1:]
		new_cell = slice.read_ref()
		#print(f"deser_ref new_cell: {json.dumps(new_cell, indent=4)}")
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

	def deser_cell_as_dict(self, slice):
		bit_stream = slice.bit_stream
		data_len = bit_stream.len - bit_stream.pos
		data = bit_stream.read(data_len)
		if self.to_json == True:
			data = bits2hex(data)
		start = slice.refs_pos
		end = len(slice.refs)
		refs = list()
		for i in range(start, end):
			new_cell = slice.refs[i]
			new_slice = Slice(new_cell)
			buff = self.deser_cell_as_dict(new_slice)
			refs.append(buff)
		result = Dict()
		result["@name"] = "Cell"
		result["special"] = slice.special
		result["bits_len"] = slice.bits_len
		result["level"] = slice.level
		result["data"] = data
		result["refs"] = refs
		result.to_class()
		return result
	#end define
	
	def deser_cell_as_line(self, slice):
		bit_stream = slice.bit_stream
		data_len = bit_stream.len - bit_stream.pos
		data = bit_stream.read(data_len)
		if self.to_json == True:
			data = bits2hex(data)
		start = slice.refs_pos
		end = len(slice.refs)
		for i in range(start, end):
			new_cell = slice.refs[i]
			new_slice = Slice(new_cell)
			data += self.deser_cell_as_line(new_slice)
		return data
	#end define
	
	def deser_flags(self, slice, var_type):
		flags = self.buff_result.get("flags")
		var_in_flags, var_type = self.is_var_in_flags(var_type, flags)
		if var_in_flags == True:
			var_value = self.deser_types(slice, var_type)
			return var_value
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
	
	def deser_special_cell(self, slice, var_type, subvars=None):
		prefix = slice.show_bytes(1)
		#print(f"deser_special_cell: {var_type}, {slice}, {prefix.hex}")
		if prefix.hex == '01':
			# deserialize PRUNNED_BRANCH as nothing
			prefix = slice.read_bytes(1)
			unknown = slice.read_bytes(1)
			virtual_hash = slice.read_bits(256).hex
			depth = slice.read_bits(16).uint
			var_value = None
		elif prefix.hex == '02':
			# deserialize MerkleUpdate according to scheme
			slice.special = False
			var_value = self.deser_types(slice, var_type, subvars)
		elif prefix.hex == '03':
			# deserialize MERKLE_PROOF according to scheme
			slice.special = False
			var_value = self.deser_types(slice, var_type, subvars)
		elif prefix.hex == '04':
			# deserialize LIBRARY
			#raise Exception("deserialize LIBRARY not implemented")
			var_value = None
		else:
			raise Exception(f"deserialize UNKNOWN with prefix `{prefix.hex}` not implemented")
		return var_value
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
				cell.bits_len += 1*8 + 8*8
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
		cell.bits_len += 3*8
		return cell
	#end define
#end class

class TlbScheme:
	def __init__(self, text):
		self.name = None
		self.class_name = None
		self.class_vars = list()
		self.vars = None
		self.prefix_bit = None
		self.is_link = False
		self.parse(text)
	#end define
	
	def __str__(self):
		result = f"<TlbScheme {self.name}${self.prefix_bit} ... = {self.class_name}>"
		return result
	#end define
	
	def __repr__(self):
		return self.__str__()
	#end define
	
	def __eq__(self, scheme):
		return (self.name == scheme.name and
			self.class_name == scheme.class_name and
			self.prefix_bit == scheme.prefix_bit and
			self.class_vars == scheme.class_vars)
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
		
		self.class_vars = split_string(class_text)
		self.class_name = self.class_vars.pop(0)
		#print(f"class_name: {self.class_name}, class_vars: {self.class_vars}")
		
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
		else:
			self.name = name_text
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
				var_name = "_"
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
