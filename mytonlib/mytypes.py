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

class Cell:
	def __init__(self):
		self.special = False
		self.bits_len = 0
		self.level = 0
		self.data = bytes()
		self.refs = list()
		self.index = None
	#end define
	
	def __eq__(self, cell):
		return self.data == cell.data
	#end define
	
	def __str__(self):
		data_hex = None
		special_text = None
		if self.data is not None:
			data_hex = self.data.hex()
		if self.special == True:
			special_text = "Special"
		result = f"<{special_text} Cell {self.bits_len}:{data_hex}={len(self.refs)}>"
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
#end class

def cells2dict(cells, to_json=False):
	result = list()
	for cell in cells:
		buff = cell2dict(cell, to_json=to_json)
		result.append(buff)
	return result
#end define

def cell2dict(cell, to_json=False):
	if type(cell) == list:
		return cells2dict(cell, to_json=to_json)
	data = cell.data
	if to_json is True:
		data = data.hex()
	result = Dict()
	result["@name"] = "Cell"
	result["special"] = cell.special
	result["bits_len"] = cell.bits_len
	result["level"] = cell.level
	result["data"] = data
	#result["bin"] = BitStream(cell.data).bin
	result["refs"] = cells2dict(cell.refs, to_json=to_json)
	result.to_class()
	return result
#end define

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
		for key, value in self.items():
			self[key] = getattr(self, key)
		#end for
#end class
