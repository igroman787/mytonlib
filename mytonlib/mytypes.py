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
	
	def copy(self, cell):
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
		result = f"<{special_text}Slice {self.bits_len}:{self.bit_stream.pos}:{data_hex}={len(self.refs)}>"
		return result
	#end define
	
	def read_ref(self):
		result = self.refs[self.refs_pos]
		self.refs_pos += 1
		return result
	#end define
	
	def read_bits(self, read_len=None):
		bit_stream = self.bit_stream
		if read_len == None:
			read_len = bit_stream.len - bit_stream.pos
		result = bit_stream.read(read_len)
		return result
	#end define
	
	def read_bytes(self, read_len):
		result = self.read_bits(read_len*8)
		return result
	#end define
	
	def show_bits(self, show_len):
		pos_old = self.bit_stream.pos
		result = self.read_bits(show_len)
		self.bit_stream.pos = pos_old
		return result
	#end define
	
	def show_bytes(self, show_len):
		result = self.show_bits(show_len*8)
		return result
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
