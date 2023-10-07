#!/usr/bin/env python3
# -*- coding: utf_8 -*-

import time
import hashlib
import threading
from bitstring import BitStream # pip3 install bitstring


def int_be(data):
	return int.from_bytes(data, byteorder="big", signed=True)
#end define

def uint_be(data):
	return int.from_bytes(data, byteorder="big", signed=False)
#end define

def int_le(data):
	return int.from_bytes(data, byteorder="little", signed=True)
#end define

def uint_le(data):
	return int.from_bytes(data, byteorder="little", signed=False)
#end define

class Dict(dict):
	def __init__(self, *args, **kwargs):
		for item in args:
			self._parse_dict(item)
		self._parse_dict(kwargs)
	#end define

	def _parse_dict(self, d):
		for key, value in d.items():
			if type(value) in [dict, Dict]:
				value = Dict(value)
			if type(value) == list:
				value = self._parse_list(value)
			self[key] = value
	#end define

	def _parse_list(self, lst):
		result = list()
		for value in lst:
			if type(value) in [dict, Dict]:
				value = Dict(value)
			result.append(value)
		return result
	#end define

	def __setattr__(self, key, value):
		self.__dict__[key] = value
		self[key] = value
	#end define

	def __getattr__(self, key):
		return self.get(key)
	#end define
#end class

class Cell(Dict):
	def __init__(self, data=None):
		self["@type"] = "Cell"
		self.special = False
		self.bits_len = 0
		self.level = 0
		self.data = bytes()
		self.refs = list()
		if data != None and type(data) == bytes:
			self.data = data
			self.bits_len = 8 * len(data)
	#end define
	
	def __eq__(self, cell):
		return self.data == cell.data
	#end define
	
	def __str__(self):
		data_hex = None
		special_text = ""
		if self.data is not None:
			data_hex = self.data.hex()
		if self.special == True:
			special_text = "Special "
		result = f"<{special_text}Cell {self.bits_len}:{data_hex}={len(self.refs)}>"
		return result
	#end define
	
	def __repr__(self):
		return self.__str__()
	#end define
	
	def add_ref(self, cell):
		self.refs.append(cell)
	#end define
	
	def copy_from(self, cell):
		self.special = cell.special
		self.bits_len = cell.bits_len
		self.level = cell.level
		self.data = cell.data
		self.refs = cell.refs
	#end define
	
	def hash(self):
		dsc = self.get_descriptors()
		#print(f"hash_dsc: {dsc.hex()}")
		buff  = dsc + self.data
		for item in self.refs:
			depth = self.get_depth()
			depth_bytes = int.to_bytes(depth, length=2, byteorder="big")
			#print(f"depth: {depth}, {depth_bytes.hex()}")
			#print(f"c.refs[i].getHash: {item.hash().hex()}")
			item_hash = item.hash()
			buff += depth_bytes + item_hash.bytes
		result_bytes = hashlib.sha256(buff).digest()
		result = BitStream(bytes=result_bytes)
		return result
	#end define
	
	def get_descriptors(self, lvl_mask=0):
		ln = (self.bits_len // 8) * 2
		if self.bits_len % 8 != 0:
			ln += 1
		#end if
		
		spec_bit = 0
		if self.special is True:
			spec_bit = 8
		#end if
		
		a = len(self.refs) + spec_bit + lvl_mask*32
		a_byte = int.to_bytes(a, length=1, byteorder="big")
		b_byte = int.to_bytes(ln, length=1, byteorder="big")
		result = a_byte + b_byte
		return result
	#end define
	
	def get_depth(self):
		depths_list = [-1]
		for item in self.refs:
			item_depth = item.get_depth() + 1
			depths_list.append(item_depth)
		#end for
		
		depth = max(depths_list)
		return depth
	#end define
	
	def dump(self):
		result = Dict()
		result.special = self.special
		result.bits_len = self.bits_len
		result.level = self.level
		result.data = self.data.hex()
		result.refs = list()
		for ref in self.refs:
			result.refs.append(ref.dump())
		return result
	#end define
#end class

class Slice(Cell):
	def __init__(self, cell):
		self["@type"] = "Slice"
		self.special = cell.special
		self.bits_len = cell.bits_len
		self.level = cell.level
		self.bit_stream = BitStream(cell.data)
		self.refs = cell.refs
		self.refs_pos = 0
	#end define
	
	def __str__(self):
		data_hex = None
		special_text = ""
		if self.bit_stream is not None:
			data_hex = self.bit_stream.hex
		if self.special == True:
			special_text = "Special "
		result = f"<{special_text}Slice {self.bit_stream.pos}/{self.bits_len}:{data_hex}={len(self.refs)}>"
		return result
	#end define
	
	def read_ref(self):
		result = self.refs[self.refs_pos]
		self.refs_pos += 1
		return result
	#end define
	
	def read_bits(self, read_len=None):
		buff = self.read(read_len)
		return buff.bin
	#end define
	
	def read_bytes(self, read_len):
		buff = self.read(read_len*8)
		return buff.bytes
	#end define
	
	def read(self, read_len=None):
		bit_stream = self.bit_stream
		available_len = bit_stream.len - bit_stream.pos
		if read_len == None:
			read_len = available_len
		result = bit_stream.read(read_len)
		return result
	#end define
	
	def show_bits(self, show_len):
		buff = self.show(show_len)
		return buff.bin
	#end define
	
	def show_bytes(self, show_len):
		buff = self.show(show_len*8)
		return buff.bytes
	#end define
	
	def show(self, show_len=None):
		pos_old = self.bit_stream.pos
		available_len = self.bit_stream.len - self.bit_stream.pos
		if show_len == None:
			show_len = available_len
		elif show_len > available_len:
			show_len = available_len
		result = self.bit_stream.read(show_len)
		self.bit_stream.pos = pos_old
		return result
	#end define
	
	def compare_bit_prefix(self, prefix_bit, move_pos=True):
		bit_len = self.get_prefix_bit_len(prefix_bit)
		if self.show_bits(bit_len) == prefix_bit or bit_len == 0:
			if move_pos:
				self.read_bits(bit_len)
			return True
		return False
	#end define
	
	def compare_byte_prefix(self, prefix, move_pos=True):
		if type(prefix) == bytes:
			prefix_byte = prefix
		else:
			prefix_byte = bytes.fromhex(prefix)
		byte_len = len(prefix_byte)
		if self.show_bytes(byte_len) == prefix_byte:
			if move_pos:
				self.read_bytes(byte_len)
			return True
		return False
	#end define
	
	def get_prefix_bit_len(self, prefix_bit):
		prefix_bit_len = 0
		if prefix_bit != None:
			prefix_bit_len = len(prefix_bit)
		return prefix_bit_len
	#end define
	
	def to_cell(self):
		cell = Cell()
		cell.special = self.special
		cell.bits_len = self.bits_len
		cell.level = self.level
		cell.data = self.bit_stream.bytes
		cell.refs = self.refs
		return cell
	#end define
	
	def hash(self):
		return self.to_cell().hash()
	#end define
#end class

class Thread(threading.Thread):
	def __init__(self, *args, **kwargs):
		self.parent = threading.current_thread()
		self.start_time = time.time()
		self.children = list()
		if type(self.parent) == threading._MainThread and not hasattr(self.parent, "children"):
			setattr(self.parent, "children", list())
		threading.Thread.__init__(self, *args, **kwargs)
	#end define
	
	def run(self, *args, **kwargs):
		self.parent.children.append(self.name)
		threading.Thread.run(self, *args, **kwargs)
		#wait = True
		#while wait:
		#	alive_children = [thr_name for thr_name in self.children if not thr_name.startswith("_ping_thr_")]
		#	wait = len(alive_children) > 0
	#end define
	
	def __del__(self, *args, **kwargs):
		self.parent.children.remove(self.name)
	#end define
#end class

def bits2hex(bit_stream):
	data = ""
	available_len = bit_stream.len - bit_stream.pos
	while available_len >= 4:
		data += bit_stream.read(4).hex
		available_len = bit_stream.len - bit_stream.pos
	if available_len > 0:
		data += '_'
	return data
#end define
