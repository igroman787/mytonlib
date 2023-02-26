#!/usr/bin/env python3
# -*- coding: utf_8 -*-

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
	def __init__(self, **kwargs):
		for key, value in kwargs.items():
			self[key] = value
		self.to_class()
	#end define
	
	def to_class(self):
		for key, value in self.items():
			setattr(self, key, value)
		#end for
	#end define
	
	def to_dict(self):
		self["@name"] = self.__class__.__name__
		for key, value in self.__dict__.items():
			self[key] = self._json_value(value)
			#if type(value) == bytes:
			#	self["bin"] = BitStream(value).bin
		#end for
	#end define
	
	def _json_value(self, value):
		if type(value) == bytes:
			value = value.hex()
		elif type(value) == BitStream:
			value = value.hex
		return value
	#end define
#end class

class Cell(Dict):
	def __init__(self):
		self.special = False
		self.bits_len = 0
		self.level = 0
		self.data = bytes()
		self.refs = list()
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
#end class

class Slice(Cell):
	def __init__(self, cell):
		self.special = cell.special
		self.bits_len = cell.bits_len
		self.level = cell.level
		self.bit_stream = BitStream(cell.data)
		self.refs = cell.refs
		self.refs_pos = 0
		self.to_dict()
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
	
	def read(self, read_len):
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
	
	def show(self, show_len):
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
	
	def compare_bit_prefix(self, prefix_bit, move_bit_pos=True):
		bit_len = self.get_prefix_bit_len(prefix_bit)
		if self.show_bits(bit_len) == prefix_bit or bit_len == 0:
			if move_bit_pos:
				self.read_bits(bit_len)
			return True
		return False
	#end define
	
	def compare_byte_prefix(self, prefix, move_bit_pos=True):
		if type(prefix) == bytes:
			prefix_byte = prefix
		else:
			prefix_byte = bytes.fromhex(prefix)
		byte_len = len(prefix_byte)
		if self.show_bytes(byte_len) == prefix_byte:
			if move_bit_pos:
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
		cell.to_dict()
		return cell
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
